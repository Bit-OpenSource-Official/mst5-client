//! Browser-only HTTP transport used by the MST5 web bindings.
//!
//! This crate deliberately owns only the browser boundary: opaque M5oH route
//! encoding and authenticated `fetch` requests.  Cipher state, records and
//! messenger operations remain in `mst5-client`; exposing a raw TCP-like
//! socket to JavaScript would leak protocol responsibilities into the UI.

use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use js_sys::Uint8Array;
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, Response};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroize;

const USER_AGENT: &str = "OVE-MST5-M5oH/1";
const HEADER_SESSION: &str = "X-MST5-Session";
const HEADER_CHANNEL: &str = "X-MST5-Channel";
const HEADER_SEQUENCE: &str = "X-MST5-Seq";
const HEADER_EOF: &str = "X-MST5-EOF";
const MAX_GET_BYTES: usize = 23 * 1024 - 8;
const CLIENT_MAGIC: &[u8; 4] = b"RCP5";
const SERVER_MAGIC: &[u8; 4] = b"RSP5";
const TAG_LEN: usize = 16;
const PROTOCOL_NAME: &[u8] = b"Noise_NK_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"MicroMsg Secure Transport v5\0RCP5\0RSP5";
const RECORD_LABEL: &[u8] = b"MST5 record";
const PADDING_BLOCK: usize = 256;
const LARGE_PADDING_BLOCK: usize = 128;
const LARGE_PADDING_THRESHOLD: usize = 1024;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const TRANSPORT_MAJOR: u64 = 5;
const RPC_MAJOR: u64 = 1;
const RPC_MINOR: u64 = 2;
const FEATURE_MULTIPLEX: u64 = 1;
const FEATURE_STRUCTURED_ERRORS: u64 = 1 << 1;
const FEATURE_CBOR_QUERY: u64 = 1 << 2;
const FEATURE_IDEMPOTENCY: u64 = 1 << 3;
const FEATURE_DEADLINE: u64 = 1 << 4;
const FEATURE_CANCEL: u64 = 1 << 5;
const REQUIRED_FEATURES: u64 = FEATURE_MULTIPLEX
    | FEATURE_STRUCTURED_ERRORS
    | FEATURE_CBOR_QUERY
    | FEATURE_IDEMPOTENCY
    | FEATURE_DEADLINE
    | FEATURE_CANCEL;

/// Encodes the opaque eight byte node selector exactly as the router expects.
/// The byte permutation prevents the route's port and address from being
/// directly legible in the CDN query parameter.
#[wasm_bindgen]
pub fn encode_route(ipv4: String, port: u16, reserved: u16) -> Result<String, JsValue> {
    let octets = ipv4
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JsValue::from_str("route IPv4 address is invalid"))?;
    if octets.len() != 4 {
        return Err(JsValue::from_str("route IPv4 address is invalid"));
    }
    let logical = [
        (port >> 8) as u8,
        port as u8,
        octets[0],
        octets[1],
        octets[2],
        octets[3],
        (reserved >> 8) as u8,
        reserved as u8,
    ];
    // Wire positions 1..8 contain logical bytes 1,8,4,6,2,7,5,3.
    let wire = [
        logical[0], logical[7], logical[3], logical[5], logical[1], logical[6], logical[4],
        logical[2],
    ];
    Ok(URL_SAFE_NO_PAD.encode(wire))
}

/// Stateless M5oHS fetch boundary.  A higher layer supplies encrypted MST5
/// records and preserves its session id / sequence counters between calls.
#[wasm_bindgen]
pub struct M5ohFetch {
    endpoint: String,
    route: String,
}

#[wasm_bindgen]
impl M5ohFetch {
    #[wasm_bindgen(constructor)]
    pub fn new(endpoint: String, route: String) -> Result<M5ohFetch, JsValue> {
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        if !endpoint.starts_with("https://") {
            return Err(JsValue::from_str("browser M5oHS endpoint must use HTTPS"));
        }
        if route.len() != 11
            || !route
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(JsValue::from_str(
                "M5oH route must be an eight-byte base64url selector",
            ));
        }
        Ok(Self { endpoint, route })
    }

    /// Sends one encrypted upstream record.  The browser never submits a
    /// destination hostname or a plaintext protocol message to the router.
    #[wasm_bindgen]
    pub async fn upstream(
        &self,
        session: String,
        sequence: u64,
        record: Uint8Array,
        eof: bool,
    ) -> Result<Uint8Array, JsValue> {
        let mut bytes = vec![0; record.length() as usize];
        record.copy_to(&mut bytes);
        if bytes.len() > MAX_GET_BYTES {
            return Err(JsValue::from_str(
                "M5oH encrypted GET record exceeds CDN limit",
            ));
        }
        self.fetch(session, "up", sequence, Some(bytes), eof).await
    }

    /// Long-polls one encrypted downstream record.
    #[wasm_bindgen]
    pub async fn downstream(&self, session: String, sequence: u64) -> Result<Uint8Array, JsValue> {
        self.fetch(session, "down", sequence, None, false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_have_an_idempotency_nonce() {
        let command = frame_encode(2, 40, 7, b"payload").expect("command frame");
        assert!(command[12..28].iter().any(|byte| *byte != 0));

        let query = frame_encode(3, 49, 8, b"").expect("query frame");
        assert!(query[12..28].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn hello_accepts_a_hello_response() {
        assert!(successful_response(11, 11, 200));
        assert!(!successful_response(11, 4, 200));
        assert!(successful_response(2, 4, 201));
    }
}

#[derive(Clone)]
struct CipherState {
    key: [u8; 32],
    nonce: u64,
}

struct BrowserSession {
    transport: M5ohFetch,
    tunnel_id: String,
    upstream_seq: u64,
    downstream_seq: u64,
    received: Vec<u8>,
    seal: CipherState,
    open: CipherState,
    handshake_hash: [u8; 32],
    next_request: u64,
}

/// Stateful, browser-safe MST5 client. All secure-transport and frame logic
/// remains in Rust/WASM. JavaScript passes only messenger JSON commands.
#[wasm_bindgen]
pub struct Mst5Web {
    inner: RefCell<Option<BrowserSession>>,
}

#[wasm_bindgen]
impl Mst5Web {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(None),
        }
    }

    #[wasm_bindgen]
    pub async fn connect(
        &self,
        endpoint: String,
        destination: String,
        server_public_key_b64: String,
        token: String,
        device_model: String,
    ) -> Result<(), JsValue> {
        let mut session = establish_session(endpoint, destination, server_public_key_b64).await?;
        authenticate_session(&mut session, token, device_model).await?;
        *self.inner.borrow_mut() = Some(session);
        Ok(())
    }

    /// Opens an authenticated encrypted transport with the server's anonymous
    /// principal.  Only `/login`, `/register` and email-auth operations are
    /// permitted until one of them succeeds; password input never crosses the
    /// browser's plaintext HTTP boundary.
    #[wasm_bindgen]
    pub async fn connect_anonymous(
        &self,
        endpoint: String,
        destination: String,
        server_public_key_b64: String,
        device_model: String,
    ) -> Result<(), JsValue> {
        let mut session = establish_session(endpoint, destination, server_public_key_b64).await?;
        authenticate_session(&mut session, String::new(), device_model).await?;
        *self.inner.borrow_mut() = Some(session);
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn command(&self, command: JsValue) -> Result<JsValue, JsValue> {
        let input: JsonValue = serde_wasm_bindgen::from_value(command)
            .map_err(|_| JsValue::from_str("invalid messenger JSON command"))?;
        let object = input
            .as_object()
            .ok_or_else(|| JsValue::from_str("messenger command must be an object"))?;
        let method = object
            .get("method")
            .and_then(JsonValue::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let raw_path = object
            .get("path")
            .and_then(JsonValue::as_str)
            .unwrap_or("/");
        let (path, query) = raw_path
            .split_once('?')
            .map_or((raw_path, None), |(path, query)| (path, Some(query)));
        let code = operation(&method, path)?;
        let payload = if method == "GET" {
            query
                .map(|value| {
                    JsonValue::Object(JsonMap::from_iter([(
                        "query".to_owned(),
                        JsonValue::String(value.to_owned()),
                    )]))
                })
                .unwrap_or_else(|| JsonValue::Object(JsonMap::new()))
        } else {
            object
                .get("body")
                .cloned()
                .unwrap_or_else(|| JsonValue::Object(JsonMap::new()))
        };
        let mut borrow = self.inner.borrow_mut();
        let session = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("MST5 is not connected"))?;
        let result = session
            .request(if method == "GET" { 3 } else { 2 }, code, payload)
            .await?;
        if !result.0 {
            return Err(JsValue::from_str(&result.1));
        }
        serde_wasm_bindgen::to_value(&result.2)
            .map_err(|_| JsValue::from_str("cannot return MST5 response"))
    }

    #[wasm_bindgen]
    pub async fn close(&self) -> Result<(), JsValue> {
        *self.inner.borrow_mut() = None;
        Ok(())
    }
}

async fn establish_session(
    endpoint: String,
    destination: String,
    server_public_key_b64: String,
) -> Result<BrowserSession, JsValue> {
    let (ip, port) = parse_destination(&destination)?;
    let route = encode_route(ip.to_string(), port, 0)?;
    let key = decode_server_key(&server_public_key_b64)?;
    let transport = M5ohFetch::new(endpoint, route)?;
    let mut random = [0u8; 18];
    getrandom::fill(&mut random)
        .map_err(|_| JsValue::from_str("browser random generator is unavailable"))?;
    let tunnel_id = URL_SAFE_NO_PAD.encode(random);
    // seq=0 makes the router establish its upstream TCP connection before
    // the Noise initiator sends a byte.
    transport.upstream_bytes(&tunnel_id, 0, &[], false).await?;
    let mut session = handshake(transport, tunnel_id, key).await?;
    session.negotiate().await?;
    Ok(session)
}

async fn authenticate_session(
    session: &mut BrowserSession,
    token: String,
    device_model: String,
) -> Result<(), JsValue> {
    let auth = JsonValue::Object(JsonMap::from_iter([
        ("token".to_owned(), JsonValue::String(token)),
        (
            "client_name".to_owned(),
            JsonValue::String("OVE Web".to_owned()),
        ),
        (
            "device_model".to_owned(),
            JsonValue::String(device_model.chars().take(128).collect()),
        ),
    ]));
    let result = session.request(1, 0, auth).await?;
    if !result.0 {
        return Err(JsValue::from_str(&format!(
            "MST5 authentication failed: {}",
            result.1
        )));
    }
    Ok(())
}

impl BrowserSession {
    async fn negotiate(&mut self) -> Result<(), JsValue> {
        let payload = JsonValue::Object(JsonMap::from_iter([
            (
                "transport_major".to_owned(),
                JsonValue::from(TRANSPORT_MAJOR),
            ),
            ("rpc_major".to_owned(), JsonValue::from(RPC_MAJOR)),
            ("rpc_minor".to_owned(), JsonValue::from(RPC_MINOR)),
            ("features".to_owned(), JsonValue::from(REQUIRED_FEATURES)),
            (
                "required_features".to_owned(),
                JsonValue::from(REQUIRED_FEATURES),
            ),
            (
                "max_frame".to_owned(),
                JsonValue::from(MAX_RECORD_BYTES as u64),
            ),
        ]));
        let response = self.request(11, 0, payload).await?;
        if !response.0 {
            return Err(JsValue::from_str(&format!(
                "MST5 HELLO failed: {}",
                response.1
            )));
        }
        let body = response
            .2
            .as_object()
            .ok_or_else(|| JsValue::from_str("MST5 SERVER_HELLO is invalid"))?;
        if body.get("transport_major").and_then(JsonValue::as_u64) != Some(TRANSPORT_MAJOR)
            || body.get("rpc_major").and_then(JsonValue::as_u64) != Some(RPC_MAJOR)
            || body
                .get("features")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0)
                & REQUIRED_FEATURES
                != REQUIRED_FEATURES
        {
            return Err(JsValue::from_str(
                "MST5 SERVER_HELLO omitted required capabilities",
            ));
        }
        Ok(())
    }

    async fn request(
        &mut self,
        kind: u8,
        code: u16,
        body: JsonValue,
    ) -> Result<(bool, String, JsonValue), JsValue> {
        let id = if kind == 11 {
            0
        } else {
            let value = self.next_request;
            self.next_request = self
                .next_request
                .checked_add(1)
                .ok_or_else(|| JsValue::from_str("MST5 request id exhausted"))?;
            value
        };
        let payload = serde_cbor::to_vec(&body)
            .map_err(|_| JsValue::from_str("cannot encode MST5 command"))?;
        let frame = frame_encode(kind, code, id, &payload)?;
        self.write_record(&frame).await?;
        loop {
            let frame = self.read_record().await?;
            let decoded = frame_decode(&frame)?;
            if decoded.id != id {
                continue;
            }
            let value: JsonValue = serde_cbor::from_slice(&decoded.payload)
                .map_err(|_| JsValue::from_str("invalid CBOR response"))?;
            let ok = successful_response(kind, decoded.kind, decoded.code);
            let reason = value
                .get("message")
                .and_then(JsonValue::as_str)
                .unwrap_or("MST5 request failed")
                .to_owned();
            return Ok((ok, reason, value));
        }
    }

    async fn write_record(&mut self, frame: &[u8]) -> Result<(), JsValue> {
        let record = seal_record(&mut self.seal, &self.handshake_hash, frame)?;
        let mut wire = Vec::with_capacity(4 + record.len());
        wire.extend_from_slice(&(record.len() as u32).to_be_bytes());
        wire.extend_from_slice(&record);
        self.transport
            .upstream_bytes(&self.tunnel_id, self.upstream_seq, &wire, false)
            .await?;
        self.upstream_seq = self
            .upstream_seq
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("M5oH upload sequence exhausted"))?;
        Ok(())
    }

    async fn read_record(&mut self) -> Result<Vec<u8>, JsValue> {
        let size = self.read_exact(4).await?;
        let length = u32::from_be_bytes(
            size.as_slice()
                .try_into()
                .map_err(|_| JsValue::from_str("invalid MST5 record header"))?,
        ) as usize;
        if length < 24 || length > MAX_RECORD_BYTES + 512 {
            return Err(JsValue::from_str("invalid MST5 record length"));
        }
        let record = self.read_exact(length).await?;
        open_record(&mut self.open, &self.handshake_hash, &record)
    }

    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, JsValue> {
        while self.received.len() < length {
            let bytes = self
                .transport
                .downstream_bytes(&self.tunnel_id, self.downstream_seq)
                .await?;
            self.downstream_seq = self
                .downstream_seq
                .checked_add(1)
                .ok_or_else(|| JsValue::from_str("M5oH download sequence exhausted"))?;
            self.received.extend_from_slice(&bytes);
        }
        Ok(self.received.drain(..length).collect())
    }
}

async fn handshake(
    transport: M5ohFetch,
    tunnel_id: String,
    server_key: [u8; 32],
) -> Result<BrowserSession, JsValue> {
    let server_static = PublicKey::from(server_key);
    let client_private = ReusableSecret::random();
    let client_public = PublicKey::from(&client_private);
    let public = client_public.to_bytes();
    let mut state = SymmetricState::new(&server_key);
    state.mix_hash(&public);
    let es = client_private.diffie_hellman(&server_static);
    require_shared(es.as_bytes())?;
    state.mix_key(es.as_bytes());
    let tag = state.encrypt_and_hash(&[])?;
    let mut hello = Vec::with_capacity(54);
    hello.extend_from_slice(CLIENT_MAGIC);
    hello.extend_from_slice(&(48u16).to_be_bytes());
    hello.extend_from_slice(&public);
    hello.extend_from_slice(&tag);
    transport
        .upstream_bytes(&tunnel_id, 1, &hello, false)
        .await?;
    let mut received = Vec::new();
    let mut down = 0;
    while received.len() < 54 {
        let body = transport.downstream_bytes(&tunnel_id, down).await?;
        down += 1;
        received.extend_from_slice(&body);
    }
    if &received[..4] != SERVER_MAGIC || u16::from_be_bytes([received[4], received[5]]) != 48 {
        return Err(JsValue::from_str("invalid MST5 server hello"));
    }
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&received[6..38]);
    state.mix_hash(&ephemeral);
    let ee = client_private.diffie_hellman(&PublicKey::from(ephemeral));
    require_shared(ee.as_bytes())?;
    state.mix_key(ee.as_bytes());
    if !state.decrypt_and_hash(&received[38..54])?.is_empty() {
        return Err(JsValue::from_str("invalid MST5 server handshake"));
    }
    let (seal, open) = state.split();
    Ok(BrowserSession {
        transport,
        tunnel_id,
        upstream_seq: 2,
        downstream_seq: down,
        received: received.split_off(54),
        seal,
        open,
        handshake_hash: state.hash,
        next_request: 1,
    })
}

struct SymmetricState {
    key: [u8; 32],
    hash: [u8; 32],
    cipher: Option<[u8; 32]>,
    nonce: u64,
}
impl SymmetricState {
    fn new(server: &[u8; 32]) -> Self {
        let mut initial = [0; 32];
        initial.copy_from_slice(PROTOCOL_NAME);
        let mut value = Self {
            key: initial,
            hash: initial,
            cipher: None,
            nonce: 0,
        };
        value.mix_hash(PROLOGUE);
        value.mix_hash(server);
        value
    }
    fn mix_hash(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.hash);
        input.extend_from_slice(data);
        self.hash = Sha256::digest(&input).into();
    }
    fn mix_key(&mut self, input: &[u8]) {
        let (key, cipher) = hkdf(&self.key, input);
        self.key = key;
        self.cipher = Some(cipher);
        self.nonce = 0;
    }
    fn encrypt_and_hash(&mut self, value: &[u8]) -> Result<Vec<u8>, JsValue> {
        let output = match self.cipher {
            Some(key) => {
                let result = aead_encrypt(&key, self.nonce, &self.hash, value)?;
                self.nonce += 1;
                result
            }
            None => value.to_vec(),
        };
        self.mix_hash(&output);
        Ok(output)
    }
    fn decrypt_and_hash(&mut self, value: &[u8]) -> Result<Vec<u8>, JsValue> {
        let output = match self.cipher {
            Some(key) => {
                let result = aead_decrypt(&key, self.nonce, &self.hash, value)?;
                self.nonce += 1;
                result
            }
            None => value.to_vec(),
        };
        self.mix_hash(value);
        Ok(output)
    }
    fn split(&self) -> (CipherState, CipherState) {
        let (first, second) = hkdf(&self.key, &[]);
        (
            CipherState {
                key: first,
                nonce: 0,
            },
            CipherState {
                key: second,
                nonce: 0,
            },
        )
    }
}

fn seal_record(
    cipher: &mut CipherState,
    hash: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let base = 5 + payload.len();
    let block = if base <= LARGE_PADDING_THRESHOLD {
        PADDING_BLOCK
    } else {
        LARGE_PADDING_BLOCK
    };
    let padded = (base + block - 1) / block * block;
    let mut plain = vec![0; padded];
    plain[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    plain[5..5 + payload.len()].copy_from_slice(payload);
    let sequence = cipher.nonce;
    let length = 8 + plain.len() + TAG_LEN;
    let aad = record_aad(hash, length, sequence)?;
    let encrypted = aead_encrypt(&cipher.key, sequence, &aad, &plain)?;
    cipher.nonce += 1;
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&encrypted);
    Ok(out)
}
fn open_record(
    cipher: &mut CipherState,
    hash: &[u8; 32],
    record: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if record.len() < 24 {
        return Err(JsValue::from_str("short MST5 encrypted record"));
    }
    let sequence = u64::from_be_bytes(
        record[..8]
            .try_into()
            .map_err(|_| JsValue::from_str("invalid record sequence"))?,
    );
    if sequence != cipher.nonce {
        return Err(JsValue::from_str("MST5 encrypted record sequence mismatch"));
    }
    let aad = record_aad(hash, record.len(), sequence)?;
    let plain = aead_decrypt(&cipher.key, sequence, &aad, &record[8..])?;
    cipher.nonce += 1;
    if plain.len() < 5 || plain[0] != 0 {
        return Err(JsValue::from_str("invalid MST5 secure transport plaintext"));
    }
    let length = u32::from_be_bytes(
        plain[1..5]
            .try_into()
            .map_err(|_| JsValue::from_str("invalid plaintext length"))?,
    ) as usize;
    if 5 + length > plain.len() || plain[5 + length..].iter().any(|value| *value != 0) {
        return Err(JsValue::from_str("invalid secure transport padding"));
    }
    Ok(plain[5..5 + length].to_vec())
}

struct Frame {
    kind: u8,
    code: u16,
    id: u64,
    payload: Vec<u8>,
}
fn frame_encode(kind: u8, code: u16, id: u64, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(JsValue::from_str("MST5 frame too large"));
    }
    let mut out = Vec::with_capacity(40 + payload.len());
    let mut request_nonce = [0u8; 16];
    // COMMANDs are idempotency-protected by the server. Queries, auth and
    // stream frames intentionally retain an all-zero nonce.
    if kind == 2 {
        getrandom::fill(&mut request_nonce)
            .map_err(|_| JsValue::from_str("browser random generator is unavailable"))?;
    }
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&request_nonce);
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}
fn frame_decode(input: &[u8]) -> Result<Frame, JsValue> {
    if input.len() < 40 || input[1] != 0 {
        return Err(JsValue::from_str("invalid MST5 frame"));
    }
    let size = u32::from_be_bytes(
        input[36..40]
            .try_into()
            .map_err(|_| JsValue::from_str("invalid MST5 frame size"))?,
    ) as usize;
    if input.len() != 40 + size {
        return Err(JsValue::from_str("invalid MST5 frame size"));
    }
    Ok(Frame {
        kind: input[0],
        code: u16::from_be_bytes([input[2], input[3]]),
        id: u64::from_be_bytes(
            input[4..12]
                .try_into()
                .map_err(|_| JsValue::from_str("invalid MST5 frame id"))?,
        ),
        payload: input[40..].to_vec(),
    })
}

fn successful_response(request_kind: u8, response_kind: u8, code: u16) -> bool {
    // HELLO is acknowledged with another HELLO frame; all remaining request
    // types use RESULT. Treating negotiation as RESULT made valid browser
    // M5oHS sessions fail before authentication.
    let expected_kind = if request_kind == 11 { 11 } else { 4 };
    response_kind == expected_kind && (200..300).contains(&code)
}

fn aead_nonce(value: u64) -> [u8; 12] {
    let mut out = [0; 12];
    out[4..].copy_from_slice(&value.to_le_bytes());
    out
}
fn aead_encrypt(key: &[u8; 32], nonce: u64, aad: &[u8], value: &[u8]) -> Result<Vec<u8>, JsValue> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| JsValue::from_str("invalid cipher key"))?
        .encrypt(
            Nonce::from_slice(&aead_nonce(nonce)),
            Payload { msg: value, aad },
        )
        .map_err(|_| JsValue::from_str("MST5 encryption failed"))
}
fn aead_decrypt(key: &[u8; 32], nonce: u64, aad: &[u8], value: &[u8]) -> Result<Vec<u8>, JsValue> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| JsValue::from_str("invalid cipher key"))?
        .decrypt(
            Nonce::from_slice(&aead_nonce(nonce)),
            Payload { msg: value, aad },
        )
        .map_err(|_| JsValue::from_str("MST5 authentication failed"))
}
fn hkdf(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(key), input);
    let mut out = [0; 64];
    hkdf.expand(&[], &mut out).expect("fixed output length");
    let mut first = [0; 32];
    let mut second = [0; 32];
    first.copy_from_slice(&out[..32]);
    second.copy_from_slice(&out[32..]);
    out.zeroize();
    (first, second)
}
fn record_aad(hash: &[u8; 32], length: usize, sequence: u64) -> Result<Vec<u8>, JsValue> {
    let mut out = Vec::with_capacity(55);
    out.extend_from_slice(RECORD_LABEL);
    out.extend_from_slice(hash);
    out.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| JsValue::from_str("record too large"))?
            .to_be_bytes(),
    );
    out.extend_from_slice(&sequence.to_be_bytes());
    Ok(out)
}
fn require_shared(value: &[u8; 32]) -> Result<(), JsValue> {
    if value.iter().all(|value| *value == 0) {
        Err(JsValue::from_str("invalid MST5 key exchange"))
    } else {
        Ok(())
    }
}
fn decode_server_key(value: &str) -> Result<[u8; 32], JsValue> {
    let bytes = STANDARD
        .decode(value.trim())
        .map_err(|_| JsValue::from_str("invalid MST5 server public key"))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str("MST5 server public key must be 32 bytes"))
}
fn parse_destination(value: &str) -> Result<(&str, u16), JsValue> {
    let (ip, port) = value
        .rsplit_once(':')
        .ok_or_else(|| JsValue::from_str("invalid M5oH destination"))?;
    Ok((
        ip,
        port.parse()
            .map_err(|_| JsValue::from_str("invalid M5oH port"))?,
    ))
}

// Keep this ABI mapping in the SDK boundary. Web UI code uses paths only,
// matching the native MessengerCore JSON contract.
fn operation(method: &str, path: &str) -> Result<u16, JsValue> {
    let code = match (method, path) {
        ("POST", "/register") => 1,
        ("POST", "/login") => 2,
        ("POST", "/auth/email/start") => 3,
        ("POST", "/auth/email/verify") => 4,
        ("GET", "/me") => 5,
        ("POST", "/account/delete") => 6,
        ("POST", "/username") => 7,
        ("POST", "/name") => 8,
        ("POST", "/privacy") => 9,
        ("GET", "/contacts") => 10,
        ("POST", "/contacts/add") => 11,
        ("POST", "/contacts/delete") => 12,
        ("POST", "/groups") => 13,
        ("POST", "/channels") => 14,
        ("POST", "/chats/title") => 15,
        ("POST", "/channels/username") => 16,
        ("POST", "/channels/comments/settings") => 17,
        ("POST", "/channels/comments/send") => 18,
        ("GET", "/channels/comments") => 19,
        ("POST", "/chats/members/add") => 20,
        ("POST", "/chats/members/remove") => 21,
        ("POST", "/cloud-password") => 22,
        ("POST", "/cloud-password/reset") => 23,
        ("GET", "/sessions") => 24,
        ("POST", "/sessions/revoke") => 25,
        ("POST", "/sessions/revoke-others") => 26,
        ("POST", "/bots") => 27,
        ("POST", "/bots/token/reset") => 28,
        ("POST", "/e2e/key") => 29,
        ("GET", "/e2e/key") => 30,
        ("POST", "/e2e/backup") => 31,
        ("GET", "/e2e/backup") => 32,
        ("POST", "/e2e/reset") => 33,
        ("GET", "/wallet") => 34,
        ("POST", "/wallet/send") => 35,
        ("GET", "/wallet/history") => 36,
        ("POST", "/call") => 37,
        ("POST", "/voice-ticket") => 38,
        ("GET", "/voice/participants") => 39,
        ("POST", "/send") => 40,
        ("POST", "/edit") => 41,
        ("POST", "/callback") => 42,
        ("POST", "/reactions") => 43,
        ("POST", "/reactions/paid") => 44,
        ("POST", "/read") => 45,
        ("POST", "/delete") => 46,
        ("POST", "/favorite") => 47,
        ("GET", "/nodes/status") => 48,
        ("GET", "/chats") => 49,
        ("POST", "/chats/delete") => 50,
        ("POST", "/users/ban") => 51,
        ("POST", "/users/unban") => 52,
        ("GET", "/history") => 53,
        ("GET", "/updates") => 54,
        ("GET", "/oauth/device/request") => 55,
        ("POST", "/oauth/device/decision") => 56,
        ("GET", "/file/ticket") => 57,
        ("POST", "/forward") => 58,
        ("POST", "/media/quote") => 59,
        ("POST", "/messages/prepare") => 71,
        ("POST", "/messages/commit") => 72,
        ("POST", "/messages/cancel") => 73,
        ("POST", "/avatars/prepare") => 86,
        ("POST", "/avatars/commit") => 87,
        ("POST", "/avatars/delete") => 88,
        ("POST", "/profiles/description") => 74,
        ("GET", "/bots/commands") => 79,
        ("GET", "/stickers/packs") => 80,
        ("GET", "/stickers/pack") => 81,
        ("POST", "/stickers/packs") => 82,
        ("POST", "/stickers/packs/purchase") => 83,
        ("POST", "/stickers/send") => 84,
        ("POST", "/stickers/packs/price") => 85,
        _ => {
            return Err(JsValue::from_str(&format!(
                "unsupported MST5 operation {method} {path}"
            )))
        }
    };
    Ok(code)
}

impl M5ohFetch {
    async fn upstream_bytes(
        &self,
        session: &str,
        sequence: u64,
        record: &[u8],
        eof: bool,
    ) -> Result<Vec<u8>, JsValue> {
        if record.len() > MAX_GET_BYTES {
            return Err(JsValue::from_str(
                "M5oH encrypted GET record exceeds CDN limit",
            ));
        }
        self.fetch(
            session.to_string(),
            "up",
            sequence,
            Some(record.to_vec()),
            eof,
        )
        .await
        .map(|body| body.to_vec())
    }

    async fn downstream_bytes(&self, session: &str, sequence: u64) -> Result<Vec<u8>, JsValue> {
        self.fetch(session.to_string(), "down", sequence, None, false)
            .await
            .map(|body| body.to_vec())
    }

    async fn fetch(
        &self,
        session: String,
        channel: &str,
        sequence: u64,
        record: Option<Vec<u8>>,
        eof: bool,
    ) -> Result<Uint8Array, JsValue> {
        let url = match record {
            Some(record) => {
                let mut packet = URL_SAFE_NO_PAD
                    .decode(&self.route)
                    .map_err(|_| JsValue::from_str("invalid M5oH route selector"))?;
                packet.extend_from_slice(&record);
                format!("{}/?r={}", self.endpoint, URL_SAFE_NO_PAD.encode(packet))
            }
            // Downstream has no payload, but still carries the opaque route
            // prefix.  The router never learns a target from an HTTP header.
            None => format!("{}/?r={}", self.endpoint, self.route),
        };
        let headers = Headers::new()?;
        headers.set(HEADER_SESSION, &session)?;
        headers.set(HEADER_CHANNEL, channel)?;
        headers.set(HEADER_SEQUENCE, &sequence.to_string())?;
        headers.set("Accept", "application/octet-stream")?;
        // Browsers do not allow a caller to forge User-Agent.  Session/channel
        // headers are therefore the browser-safe M5oH shape; the router uses
        // the opaque selector in `r` and never accepts a target header.
        let _ = USER_AGENT;
        if eof {
            headers.set(HEADER_EOF, "1")?;
        }

        let init = RequestInit::new();
        init.set_method("GET");
        init.set_headers(&headers);
        init.set_mode(web_sys::RequestMode::Cors);
        let request = Request::new_with_str_and_init(&url, &init)?;
        let window =
            web_sys::window().ok_or_else(|| JsValue::from_str("browser window is unavailable"))?;
        let response: Response = JsFuture::from(window.fetch_with_request(&request))
            .await?
            .dyn_into()?;
        if !response.ok() {
            return Err(JsValue::from_str(&format!(
                "M5oH HTTP {}",
                response.status()
            )));
        }
        let body = JsFuture::from(response.array_buffer()?).await?;
        Ok(Uint8Array::new(&body))
    }
}
