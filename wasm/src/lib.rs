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
use flate2::read::DeflateDecoder;
use hkdf::Hkdf;
use js_sys::{Function, Promise, Uint8Array};
use mst5_e2e_core as e2e;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use wasm_bindgen::{closure::Closure, prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, Response};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroize;

const USER_AGENT: &str = "OVE-MST5-M5oH/1";
const HEADER_SESSION: &str = "X-MST5-Session";
const HEADER_CHANNEL: &str = "X-MST5-Channel";
const HEADER_SEQUENCE: &str = "X-MST5-Seq";
const HEADER_EOF: &str = "X-MST5-EOF";
const HEADER_STATUS: &str = "X-MST5-Status";
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
const FEATURE_MEDIA_STREAMS: u64 = 1 << 6;
const REQUIRED_FEATURES: u64 = FEATURE_MULTIPLEX
    | FEATURE_STRUCTURED_ERRORS
    | FEATURE_CBOR_QUERY
    | FEATURE_IDEMPOTENCY
    | FEATURE_DEADLINE
    | FEATURE_CANCEL;
const REQUIRED_MEDIA_FEATURES: u64 = FEATURE_STRUCTURED_ERRORS | FEATURE_MEDIA_STREAMS;
// A M5oH upstream request has a 23 KiB envelope cap.  Leave ample room for
// the frame header, encrypted record header/tag and padding instead of
// relying on the media node's much larger 256 KiB native-TCP chunk size.
const BROWSER_MEDIA_CHUNK: usize = 16 * 1024;
// M5oH downstream is a GET-only mailbox.  An empty `OK` response means the
// router has no bytes yet; it is not an invitation to spin another GET in the
// same event-loop turn.  Keep this policy in the SDK, rather than every UI.
const M5OH_EMPTY_POLL_INITIAL_MS: i32 = 125;
const M5OH_EMPTY_POLL_MAX_MS: i32 = 2_000;
const MST5_KIND_AUTH: u8 = 1;
const MST5_KIND_COMMAND: u8 = 2;
const MST5_FLAG_DEFLATE: u8 = 1;
const MST5_KIND_RESULT: u8 = 4;
const MST5_KIND_ACK: u8 = 6;
const MST5_KIND_ERROR: u8 = 7;
const MST5_KIND_HELLO: u8 = 11;
const MST5_KIND_STREAM_OPEN: u8 = 14;
const MST5_KIND_STREAM_DATA: u8 = 15;
const MST5_KIND_STREAM_END: u8 = 16;
const MST5_KIND_STREAM_ABORT: u8 = 17;
const MEDIA_OP_UPLOAD: u16 = 1;
const MEDIA_OP_DOWNLOAD: u16 = 2;
// A browser has to materialize a Blob before it can display or save it. Keep
// that explicit bound below the usual tab memory budget instead of accepting a
// server-provided size that could make a page allocate unbounded memory.
const MAX_BROWSER_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
const EMBEDDED_ACCOUNT_PUBLIC_KEY: &str = env!("CRYPT_SERVER_PUBLIC_KEY_B64");

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

        let query = frame_encode(3, 51, 8, b"").expect("query frame");
        assert!(query[12..28].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn hello_accepts_a_hello_response() {
        assert!(successful_response(11, 11, 200));
        assert!(!successful_response(11, 4, 200));
        assert!(successful_response(2, 4, 201));
    }

    #[test]
    fn email_auth_extracts_the_session_token_before_js_conversion() {
        assert_eq!(
            auth_session_token(&serde_json::json!({ "token": "session-value" })),
            Some("session-value".to_string())
        );
        assert_eq!(auth_session_token(&serde_json::json!({ "token": "" })), None);
        assert_eq!(auth_session_token(&serde_json::json!({ "ok": true })), None);
    }

    #[test]
    fn browser_tunnel_ids_match_the_router_contract() {
        let id = browser_tunnel_id().expect("browser tunnel id");
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn messenger_operation_codes_match_the_server_contract() {
        // Keep the browser ABI in sync with micromsg/src/mst5.rs. These used
        // to be shifted by two after the server reserved operations 48 and 49,
        // which made a successful browser login fail immediately on /chats.
        // Cover every route used by the web client, including the separate
        // prepare/upload/commit media sequence.
        for ((method, path), expected) in [
            (("POST", "/register"), 1),
            (("POST", "/login"), 2),
            (("GET", "/me"), 5),
            (("POST", "/channels/username"), 16),
            (("POST", "/channels/comments/settings"), 17),
            (("POST", "/channels/comments/send"), 18),
            (("GET", "/channels/comments"), 19),
            (("GET", "/sessions"), 24),
            (("POST", "/bots"), 27),
            (("POST", "/bots/token/reset"), 28),
            (("GET", "/wallet"), 34),
            (("GET", "/wallet/history"), 36),
            (("POST", "/send"), 40),
            (("POST", "/reactions"), 43),
            (("POST", "/reactions/paid"), 44),
            (("POST", "/read"), 45),
            (("GET", "/nodes/status"), 50),
            (("GET", "/chats"), 51),
            (("POST", "/chats/delete"), 52),
            (("GET", "/history"), 55),
            (("GET", "/updates"), 56),
            (("GET", "/oauth/device/request"), 60),
            (("GET", "/file/ticket"), 65),
            (("POST", "/forward"), 69),
            (("POST", "/media/quote"), 70),
            (("POST", "/messages/prepare"), 71),
            (("POST", "/messages/commit"), 72),
            (("POST", "/messages/cancel"), 73),
            (("GET", "/bots/commands"), 79),
            (("GET", "/stickers/packs"), 80),
            (("POST", "/stickers/packs"), 82),
            (("POST", "/stickers/packs/purchase"), 83),
            (("POST", "/stickers/send"), 84),
            (("POST", "/stickers/packs/price"), 85),
            (("POST", "/pin"), 92),
            (("POST", "/polls/vote"), 93),
            (("GET", "/chats/favorites"), 94),
            (("POST", "/chats/favorite"), 95),
            (("GET", "/chats/folders"), 96),
            (("POST", "/chats/folder"), 97),
        ] {
            assert_eq!(
                operation(method, path).expect("registered operation"),
                expected
            );
        }
    }

    #[test]
    fn deflate_result_frames_are_decoded_with_a_bound() {
        let plain = b"chat list ".repeat(1024);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut encoder, &plain).expect("compress frame payload");
        let compressed = encoder.finish().expect("finish compressed frame payload");
        let mut frame = Vec::with_capacity(40 + compressed.len());
        frame.extend_from_slice(&[MST5_KIND_RESULT, MST5_FLAG_DEFLATE]);
        frame.extend_from_slice(&200u16.to_be_bytes());
        frame.extend_from_slice(&7u64.to_be_bytes());
        frame.extend_from_slice(&[0; 16]);
        frame.extend_from_slice(&0u64.to_be_bytes());
        frame.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        frame.extend_from_slice(&compressed);
        assert_eq!(
            frame_decode(&frame)
                .expect("decode compressed frame")
                .payload,
            plain
        );
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

struct BrowserMediaUpload {
    session: BrowserSession,
    id: u64,
    expected_size: usize,
    sent: usize,
    chunk_size: usize,
    digest: Sha256,
    resume_checksum: Option<String>,
}

/// A single ticket-authorized, encrypted media upload. JavaScript feeds it
/// short `File.stream()` chunks, so the full source file never has to be
/// duplicated in a WebAssembly `Uint8Array`.
#[wasm_bindgen]
pub struct Mst5MediaUpload {
    inner: RefCell<Option<BrowserMediaUpload>>,
}

struct BrowserE2eMediaUpload {
    upload: BrowserMediaUpload,
    encryptor: e2e::MediaEncryptor,
    /// Browser `File.stream()` chunks are not guaranteed to be aligned to the
    /// authenticated 64 KiB E2E-media chunks.  Retain at most one chunk here
    /// and write ciphertext straight to the MST5 stream.
    pending: Vec<u8>,
}

/// Streaming E2E media writer. Plaintext only exists transiently in the
/// browser-provided chunk and the small alignment buffer; the media node sees
/// the V2 encrypted-media container exclusively.
#[wasm_bindgen]
pub struct Mst5E2eMediaUpload {
    inner: RefCell<Option<BrowserE2eMediaUpload>>,
}

#[derive(Serialize, Deserialize)]
struct E2eEnvelopeJson {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct GroupE2eEnvelopeJson {
    version: u8,
    recipients: HashMap<String, E2eEnvelopeJson>,
}

#[derive(Serialize, Deserialize)]
struct E2eBackupJson {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Opaque application-level E2E identity. The private key is used only in
/// Rust/WASM for envelope and media operations; export is solely for placing
/// an encrypted copy in the browser's non-extractable IndexedDB key store.
#[wasm_bindgen]
pub struct Mst5E2eIdentity {
    inner: RefCell<Option<e2e::Identity>>,
}

#[wasm_bindgen]
impl Mst5E2eIdentity {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Self, JsValue> {
        Ok(Self { inner: RefCell::new(Some(e2e::Identity::generate().map_err(e2e_error)?)) })
    }

    #[wasm_bindgen(js_name = importPrivate)]
    pub fn import_private(private: Uint8Array) -> Result<Self, JsValue> {
        if private.length() != 32 { return Err(JsValue::from_str("E2E private key must be 32 bytes")); }
        let mut bytes = [0u8; 32]; private.copy_to(&mut bytes);
        let identity = e2e::Identity::from_private(bytes);
        bytes.zeroize();
        Ok(Self { inner: RefCell::new(Some(identity)) })
    }

    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(backup: JsValue, password: String) -> Result<Self, JsValue> {
        let backup = parse_backup(backup)?;
        let identity = e2e::Identity::restore(&backup, &password).map_err(e2e_error)?;
        Ok(Self { inner: RefCell::new(Some(identity)) })
    }

    #[wasm_bindgen(js_name = exportPrivate)]
    pub fn export_private(&self) -> Result<Uint8Array, JsValue> {
        let identity = self.identity()?;
        let mut private = identity.private_key();
        let result = Uint8Array::from(private.as_slice());
        private.zeroize();
        Ok(result)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<String, JsValue> {
        Ok(STANDARD.encode(self.identity()?.public_key()))
    }

    pub fn fingerprint(&self) -> Result<String, JsValue> { Ok(self.identity()?.fingerprint()) }

    #[wasm_bindgen(js_name = sealMessage)]
    pub fn seal_message(&self, peer_public_key: String, from: String, to: String, plaintext: Uint8Array) -> Result<JsValue, JsValue> {
        let peer = parse_e2e_public(&peer_public_key)?;
        let mut bytes = vec![0; plaintext.length() as usize]; plaintext.copy_to(&mut bytes);
        let envelope = self.identity()?.seal(peer, &from, &to, &bytes).map_err(e2e_error)?;
        bytes.zeroize();
        envelope_to_js(&envelope)
    }

    #[wasm_bindgen(js_name = openMessage)]
    pub fn open_message(&self, peer_public_key: String, from: String, to: String, envelope: JsValue) -> Result<Uint8Array, JsValue> {
        let peer = parse_e2e_public(&peer_public_key)?;
        let envelope = parse_envelope(envelope)?;
        let mut plaintext = self.identity()?.open(peer, &from, &to, &envelope).map_err(e2e_error)?;
        let result = Uint8Array::from(plaintext.as_slice());
        plaintext.zeroize();
        Ok(result)
    }

    #[wasm_bindgen(js_name = sealGroupMessage)]
    pub fn seal_group_message(&self, peer_keys: JsValue, from: String, plaintext: Uint8Array) -> Result<JsValue, JsValue> {
        let keys: HashMap<String, String> = serde_wasm_bindgen::from_value(peer_keys)
            .map_err(|_| JsValue::from_str("invalid group E2E recipient keys"))?;
        let recipients = keys.into_iter().map(|(id, key)| parse_e2e_public(&key).map(|key| (id, key))).collect::<Result<Vec<_>, _>>()?;
        let mut bytes = vec![0; plaintext.length() as usize];
        plaintext.copy_to(&mut bytes);
        let group = self.identity()?.seal_group(&recipients, &from, &bytes).map_err(e2e_error)?;
        bytes.zeroize();
        let recipients = group.recipients.into_iter().map(|(id, envelope)| (id, E2eEnvelopeJson { version: envelope.version, nonce: STANDARD.encode(envelope.nonce), ciphertext: STANDARD.encode(envelope.ciphertext) })).collect();
        GroupE2eEnvelopeJson { version: group.version, recipients }
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|_| JsValue::from_str("cannot encode group E2E envelope"))
    }

    #[wasm_bindgen(js_name = openGroupMessage)]
    pub fn open_group_message(&self, sender_public_key: String, sender: String, recipient: String, envelope: JsValue) -> Result<Uint8Array, JsValue> {
        let raw: GroupE2eEnvelopeJson = serde_wasm_bindgen::from_value(envelope).map_err(|_| JsValue::from_str("invalid group E2E envelope"))?;
        let recipients = raw.recipients.into_iter().map(|(id, value)| { let nonce: [u8; 24] = decode_e2e(&value.nonce, "nonce", Some(24))?.try_into().map_err(|_| JsValue::from_str("invalid group E2E nonce"))?; Ok((id, e2e::Envelope { version: value.version, nonce, ciphertext: decode_e2e(&value.ciphertext, "ciphertext", None)? })) }).collect::<Result<HashMap<_, _>, JsValue>>()?;
        let group = e2e::GroupEnvelope { version: raw.version, recipients };
        let opened = self.identity()?.open_group(parse_e2e_public(&sender_public_key)?, &sender, &recipient, &group).map_err(e2e_error)?;
        Ok(Uint8Array::from(opened.as_slice()))
    }

    #[wasm_bindgen(js_name = createBackup)]
    pub fn create_backup(&self, password: String) -> Result<JsValue, JsValue> {
        let backup = self.identity()?.backup(&password).map_err(e2e_error)?;
        backup_to_js(&backup)
    }

    #[wasm_bindgen(js_name = encryptedMediaSize)]
    pub fn encrypted_media_size(&self, plaintext_size: u64) -> Result<u64, JsValue> {
        e2e::encrypted_media_size(plaintext_size).map_err(e2e_error)
    }

    /// Derives a media-stream key that applications may wrap for multiple
    /// recipients before uploading a single ciphertext stream.
    #[wasm_bindgen(js_name = mediaKey)]
    pub fn media_key(&self, peer_public_key: String, from: String, to: String) -> Result<String, JsValue> {
        let key = self.identity()?.media_key(parse_e2e_public(&peer_public_key)?, &from, &to).map_err(e2e_error)?;
        Ok(STANDARD.encode(key))
    }

    pub fn close(&self) { self.inner.borrow_mut().take(); }
}

impl Mst5E2eIdentity {
    fn identity(&self) -> Result<std::cell::Ref<'_, e2e::Identity>, JsValue> {
        std::cell::Ref::filter_map(self.inner.borrow(), |value| value.as_ref())
            .map_err(|_| JsValue::from_str("E2E identity is closed"))
    }
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
        token: String,
        device_model: String,
    ) -> Result<(), JsValue> {
        let mut session = establish_session(
            endpoint,
            destination,
        )
        .await?;
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
        device_model: String,
    ) -> Result<(), JsValue> {
        let mut session = establish_session(
            endpoint,
            destination,
        )
        .await?;
        authenticate_session(&mut session, String::new(), device_model).await?;
        *self.inner.borrow_mut() = Some(session);
        Ok(())
    }

    /// Requests a one-time e-mail code over the current anonymous MST5
    /// session.  Keeping this operation in the SDK means a web UI never has
    /// to encode an auth opcode or interpret a transport response itself.
    #[wasm_bindgen]
    pub async fn start_email_auth(&self, email: String) -> Result<(), JsValue> {
        let email = email.trim();
        if email.is_empty() {
            return Err(JsValue::from_str("e-mail is required"));
        }
        let mut borrow = self.inner.borrow_mut();
        let session = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("MST5 is not connected"))?;
        let result = session
            .request(
                MST5_KIND_COMMAND,
                3,
                serde_json::json!({ "email": email }),
            )
            .await?;
        if result.0 {
            Ok(())
        } else {
            Err(JsValue::from_str(&result.1))
        }
    }

    /// Verifies an e-mail code and returns only the server-issued session
    /// token.  Parsing happens in Rust so differing JS object/map conversion
    /// rules cannot turn a valid auth response into a missing token.
    #[wasm_bindgen]
    pub async fn verify_email_auth(
        &self,
        email: String,
        code: String,
        cloud_password: String,
    ) -> Result<String, JsValue> {
        let mut borrow = self.inner.borrow_mut();
        let session = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("MST5 is not connected"))?;
        let result = session
            .request(
                MST5_KIND_COMMAND,
                4,
                serde_json::json!({
                    "email": email.trim(),
                    "code": code.trim(),
                    "cloud_password": cloud_password,
                }),
            )
            .await?;
        if !result.0 {
            return Err(JsValue::from_str(&result.1));
        }
        auth_session_token(&result.2)
            .ok_or_else(|| JsValue::from_str("MST5 auth response did not contain a session"))
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
        // `serde_json::Value::Object` serializes as an ES Map by default.
        // A web client consumes RPC replies as JSON, so preserve the normal
        // browser object shape all the way through nested chats, users,
        // wallets and media instead of forcing every UI to understand Map.
        result.2
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|_| JsValue::from_str("cannot return MST5 response"))
}


    /// Uploads a media object over a separate encrypted MST5 media stream.
    /// `media_endpoint` is the server-provided `raw|m5oh` endpoint; the raw
    /// endpoint is never used by a browser.  Its M5oH fallback carries only
    /// the opaque router destination, while requests go to `m5ohs_endpoint`.
    #[wasm_bindgen]
    pub async fn upload_media(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        data: Uint8Array,
    ) -> Result<(), JsValue> {
        if ticket.is_empty() || file_id.is_empty() || data.length() == 0 {
            return Err(JsValue::from_str(
                "media ticket, file id and data are required",
            ));
        }
        let destination = parse_media_destination(&media_endpoint)?;
        let mut bytes = vec![0; data.length() as usize];
        data.copy_to(&mut bytes);
        let mut session = establish_session_with_features(
            m5ohs_endpoint,
            destination,
            REQUIRED_MEDIA_FEATURES,
        )
        .await?;
        media_authenticate(&mut session, ticket).await?;
        session.upload_media(&file_id, &bytes).await
    }

    /// Opens a streaming media upload. Prefer this method for browser `File`
    /// objects; `upload_media` remains for backwards-compatible callers.
    #[wasm_bindgen]
    pub async fn begin_media_upload(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        expected_size: u64,
    ) -> Result<Mst5MediaUpload, JsValue> {
        if ticket.is_empty() || file_id.is_empty() || expected_size == 0 {
            return Err(JsValue::from_str(
                "media ticket, file id and expected size are required",
            ));
        }
        let expected_size = usize::try_from(expected_size)
            .map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(
            m5ohs_endpoint,
            destination,
            REQUIRED_MEDIA_FEATURES,
        )
        .await?;
        media_authenticate(&mut session, ticket).await?;
        let upload = BrowserMediaUpload::open(session, file_id, expected_size).await?;
        Ok(Mst5MediaUpload {
            inner: RefCell::new(Some(upload)),
        })
    }

    /// Resumes a previously interrupted upload. The caller must pass a
    /// `File.slice(offset)` stream and the SHA-256 of the complete file.
    #[wasm_bindgen]
    pub async fn begin_resumable_media_upload(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        expected_size: u64,
        offset: u64,
        sha256: String,
    ) -> Result<Mst5MediaUpload, JsValue> {
        if ticket.is_empty() || file_id.is_empty() || expected_size == 0 || offset > expected_size {
            return Err(JsValue::from_str("invalid resumable media upload arguments"));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(JsValue::from_str("invalid media checksum"));
        }
        let expected_size = usize::try_from(expected_size).map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        let offset = usize::try_from(offset).map_err(|_| JsValue::from_str("media offset is too large for this browser"))?;
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(m5ohs_endpoint, destination, REQUIRED_MEDIA_FEATURES).await?;
        media_authenticate(&mut session, ticket).await?;
        let upload = BrowserMediaUpload::open_with_offset(session, file_id, expected_size, offset, Some(sha256)).await?;
        Ok(Mst5MediaUpload { inner: RefCell::new(Some(upload)) })
    }

    /// Opens a media stream that encrypts each attachment chunk with the
    /// sender/recipient E2E session key. The upload reservation must be for
    /// `Identity.encryptedMediaSize(plaintext_size)` bytes.
    #[wasm_bindgen(js_name = beginE2eMediaUpload)]
    pub async fn begin_e2e_media_upload(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        plaintext_size: u64,
        identity: &Mst5E2eIdentity,
        peer_public_key: String,
        from: String,
        to: String,
    ) -> Result<Mst5E2eMediaUpload, JsValue> {
        if ticket.is_empty() || file_id.is_empty() || plaintext_size == 0 {
            return Err(JsValue::from_str(
                "media ticket, file id and plaintext size are required",
            ));
        }
        let encrypted_size = e2e::encrypted_media_size(plaintext_size).map_err(e2e_error)?;
        let expected_size = usize::try_from(encrypted_size)
            .map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        let peer = parse_e2e_public(&peer_public_key)?;
        let encryptor = identity
            .identity()?
            .media_encryptor(peer, &from, &to, &file_id, plaintext_size)
            .map_err(e2e_error)?;
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(
            m5ohs_endpoint,
            destination,
            REQUIRED_MEDIA_FEATURES,
        )
        .await?;
        media_authenticate(&mut session, ticket).await?;
        let mut upload = BrowserMediaUpload::open(session, file_id, expected_size).await?;
        upload.write(&encryptor.header()).await?;
        Ok(Mst5E2eMediaUpload {
            inner: RefCell::new(Some(BrowserE2eMediaUpload {
                upload,
                encryptor,
                pending: Vec::with_capacity(e2e::MEDIA_CHUNK_SIZE),
            })),
        })
    }

    /// Downloads one media object over a separate encrypted MST5 media stream.
    /// The ticket is obtained by the authenticated messenger session via
    /// `/file/ticket`; it authorizes exactly one file and expires quickly.
    #[wasm_bindgen]
    pub async fn download_media(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        expected_size: u64,
    ) -> Result<Uint8Array, JsValue> {
        if ticket.is_empty() || file_id.is_empty() || expected_size == 0 {
            return Err(JsValue::from_str(
                "media ticket, file id and expected size are required",
            ));
        }
        let expected_size = usize::try_from(expected_size)
            .map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        if expected_size > MAX_BROWSER_DOWNLOAD_BYTES {
            return Err(JsValue::from_str(
                "media file exceeds the browser download memory limit",
            ));
        }
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(
            m5ohs_endpoint,
            destination,
            REQUIRED_MEDIA_FEATURES,
        )
        .await?;
        media_authenticate(&mut session, ticket).await?;
        let bytes = session.download_media(&file_id, expected_size).await?;
        Ok(Uint8Array::from(bytes.as_slice()))
    }

    /// Streams media chunks to JavaScript without materializing the complete
    /// file. The callback receives one Uint8Array per authenticated MST5
    /// stream frame; checksum and size are verified before this resolves.
    #[wasm_bindgen(js_name = downloadMediaStream)]
    pub async fn download_media_stream(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        expected_size: u64,
        on_chunk: Function,
    ) -> Result<(), JsValue> {
        if ticket.is_empty() || file_id.is_empty() || expected_size == 0 {
            return Err(JsValue::from_str("media ticket, file id and expected size are required"));
        }
        let expected_size = usize::try_from(expected_size).map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        if expected_size > MAX_BROWSER_DOWNLOAD_BYTES { return Err(JsValue::from_str("media file exceeds the browser download memory limit")); }
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(m5ohs_endpoint, destination, REQUIRED_MEDIA_FEATURES).await?;
        media_authenticate(&mut session, ticket).await?;
        session.download_media_stream(&file_id, expected_size, &on_chunk).await
    }

    /// Downloads and decrypts an E2E media container incrementally. Ciphertext
    /// frames are authenticated and released immediately; only the final
    /// plaintext browser object is materialized for Blob display/download.
    #[wasm_bindgen(js_name = downloadE2eMedia)]
    pub async fn download_e2e_media(
        &self,
        m5ohs_endpoint: String,
        media_endpoint: String,
        ticket: String,
        file_id: String,
        expected_size: u64,
        identity: &Mst5E2eIdentity,
        peer_public_key: String,
        from: String,
        to: String,
    ) -> Result<Uint8Array, JsValue> {
        if ticket.is_empty() || file_id.is_empty() || expected_size == 0 {
            return Err(JsValue::from_str(
                "media ticket, file id and expected size are required",
            ));
        }
        let expected_size = usize::try_from(expected_size)
            .map_err(|_| JsValue::from_str("media file is too large for this browser"))?;
        if expected_size > MAX_BROWSER_DOWNLOAD_BYTES {
            return Err(JsValue::from_str(
                "media file exceeds the browser download memory limit",
            ));
        }
        let peer = parse_e2e_public(&peer_public_key)?;
        let decryptor = identity
            .identity()?
            .media_decryptor(peer, &from, &to, &file_id)
            .map_err(e2e_error)?;
        let destination = parse_media_destination(&media_endpoint)?;
        let mut session = establish_session_with_features(
            m5ohs_endpoint,
            destination,
            REQUIRED_MEDIA_FEATURES,
        )
        .await?;
        media_authenticate(&mut session, ticket).await?;
        let mut plaintext = session
            .download_e2e_media(&file_id, expected_size, decryptor)
            .await?;
        let result = Uint8Array::from(plaintext.as_slice());
        plaintext.zeroize();
        Ok(result)
    }

    #[wasm_bindgen]
    pub async fn close(&self) -> Result<(), JsValue> {
        *self.inner.borrow_mut() = None;
        Ok(())
    }
}

fn auth_session_token(value: &JsonValue) -> Option<String> {
    value
        .get("token")
        .and_then(JsonValue::as_str)
        .filter(|token| !token.trim().is_empty())
        .map(str::to_owned)
}

fn e2e_error(error: std::io::Error) -> JsValue { JsValue::from_str(&error.to_string()) }

fn decode_e2e(value: &str, field: &str, expected: Option<usize>) -> Result<Vec<u8>, JsValue> {
    let bytes = STANDARD.decode(value).map_err(|_| JsValue::from_str(&format!("invalid E2E {field}")))?;
    if expected.is_some_and(|size| bytes.len() != size) { return Err(JsValue::from_str(&format!("invalid E2E {field} length"))); }
    Ok(bytes)
}

fn parse_e2e_public(value: &str) -> Result<[u8; 32], JsValue> {
    decode_e2e(value, "public key", Some(32))?.try_into().map_err(|_| JsValue::from_str("invalid E2E public key"))
}

fn envelope_to_js(value: &e2e::Envelope) -> Result<JsValue, JsValue> {
    E2eEnvelopeJson { version: value.version, nonce: STANDARD.encode(value.nonce), ciphertext: STANDARD.encode(&value.ciphertext) }
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| JsValue::from_str("cannot encode E2E envelope"))
}

fn parse_envelope(value: JsValue) -> Result<e2e::Envelope, JsValue> {
    let raw: E2eEnvelopeJson = serde_wasm_bindgen::from_value(value).map_err(|_| JsValue::from_str("invalid E2E envelope"))?;
    let nonce: [u8; 24] = decode_e2e(&raw.nonce, "nonce", Some(24))?.try_into().map_err(|_| JsValue::from_str("invalid E2E nonce"))?;
    let ciphertext = decode_e2e(&raw.ciphertext, "ciphertext", None)?;
    Ok(e2e::Envelope { version: raw.version, nonce, ciphertext })
}

fn backup_to_js(value: &e2e::Backup) -> Result<JsValue, JsValue> {
    E2eBackupJson { version: value.version, salt: STANDARD.encode(value.salt), nonce: STANDARD.encode(value.nonce), ciphertext: STANDARD.encode(&value.ciphertext) }
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| JsValue::from_str("cannot encode E2E backup"))
}

fn parse_backup(value: JsValue) -> Result<e2e::Backup, JsValue> {
    let raw: E2eBackupJson = serde_wasm_bindgen::from_value(value).map_err(|_| JsValue::from_str("invalid E2E backup"))?;
    let salt: [u8; 16] = decode_e2e(&raw.salt, "backup salt", Some(16))?.try_into().map_err(|_| JsValue::from_str("invalid E2E backup salt"))?;
    let nonce: [u8; 24] = decode_e2e(&raw.nonce, "backup nonce", Some(24))?.try_into().map_err(|_| JsValue::from_str("invalid E2E backup nonce"))?;
    Ok(e2e::Backup { version: raw.version, salt, nonce, ciphertext: decode_e2e(&raw.ciphertext, "backup ciphertext", None)? })
}

#[wasm_bindgen]
impl Mst5MediaUpload {
    /// Sends one browser stream chunk. The bridge further splits it to stay
    /// below the M5oH CDN GET envelope limit.
    #[wasm_bindgen]
    pub async fn write(&self, data: Uint8Array) -> Result<(), JsValue> {
        if data.length() == 0 {
            return Ok(());
        }
        let mut bytes = vec![0; data.length() as usize];
        data.copy_to(&mut bytes);
        let mut borrow = self.inner.borrow_mut();
        let upload = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("media upload is already closed"))?;
        upload.write(&bytes).await
    }

    /// Verifies the browser byte count, sends STREAM_END with SHA-256 and
    /// waits for the file node's final result.
    #[wasm_bindgen]
    pub async fn finish(&self) -> Result<(), JsValue> {
        let mut borrow = self.inner.borrow_mut();
        let upload = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("media upload is already closed"))?;
        upload.finish().await?;
        *borrow = None;
        Ok(())
    }

    /// Stops an unfinished stream before the messenger cancels its upload
    /// operation and releases its reservation.
    #[wasm_bindgen]
    pub async fn abort(&self) -> Result<(), JsValue> {
        let upload = self.inner.borrow_mut().take();
        if let Some(mut upload) = upload {
            upload.abort().await?;
        }
        Ok(())
    }
}

#[wasm_bindgen]
impl Mst5E2eMediaUpload {
    /// Encrypts a browser stream chunk. It accepts arbitrary chunk boundaries
    /// while preserving the fixed chunking authenticated by the E2E format.
    #[wasm_bindgen]
    pub async fn write(&self, data: Uint8Array) -> Result<(), JsValue> {
        if data.length() == 0 {
            return Ok(());
        }
        let mut bytes = vec![0; data.length() as usize];
        data.copy_to(&mut bytes);
        let mut borrow = self.inner.borrow_mut();
        let upload = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("E2E media upload is already closed"))?;
        upload.pending.extend_from_slice(&bytes);
        bytes.zeroize();
        while upload.pending.len() >= e2e::MEDIA_CHUNK_SIZE {
            let chunk: Vec<u8> = upload.pending.drain(..e2e::MEDIA_CHUNK_SIZE).collect();
            let mut sealed = upload.encryptor.seal_chunk(&chunk).map_err(e2e_error)?;
            upload.upload.write(&sealed).await?;
            sealed.zeroize();
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn finish(&self) -> Result<(), JsValue> {
        let mut borrow = self.inner.borrow_mut();
        let upload = borrow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("E2E media upload is already closed"))?;
        if !upload.pending.is_empty() {
            let mut chunk = std::mem::take(&mut upload.pending);
            let mut sealed = upload.encryptor.seal_chunk(&chunk).map_err(e2e_error)?;
            chunk.zeroize();
            upload.upload.write(&sealed).await?;
            sealed.zeroize();
        }
        upload.encryptor.finish().map_err(e2e_error)?;
        upload.upload.finish().await?;
        *borrow = None;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn abort(&self) -> Result<(), JsValue> {
        let upload = self.inner.borrow_mut().take();
        if let Some(mut upload) = upload {
            upload.pending.zeroize();
            upload.upload.abort().await?;
        }
        Ok(())
    }
}

async fn establish_session(
    endpoint: String,
    destination: String,
) -> Result<BrowserSession, JsValue> {
    establish_session_with_features(
        endpoint,
        destination,
        REQUIRED_FEATURES,
    )
    .await
}

async fn establish_session_with_features(
    endpoint: String,
    destination: String,
    required_features: u64,
) -> Result<BrowserSession, JsValue> {
    let (ip, port) = parse_destination(&destination)?;
    let route = encode_route(ip.to_string(), port, 0)?;
    let key = decode_server_key(EMBEDDED_ACCOUNT_PUBLIC_KEY)?;
    let transport = M5ohFetch::new(endpoint, route)?;
    let tunnel_id = browser_tunnel_id()?;
    // seq=0 makes the router establish its upstream TCP connection before
    // the Noise initiator sends a byte.
    transport.upstream_bytes(&tunnel_id, 0, &[], false).await?;
    let mut session = handshake(transport, tunnel_id, key).await?;
    session.negotiate(required_features).await?;
    Ok(session)
}

/// The shared router deliberately accepts only a canonical 128-bit lowercase
/// hexadecimal session id.  It keeps this HTTP identifier separate from the
/// opaque route and encrypted MST5 data, so it remains safe to use in headers
/// and compatible with the native M5oH transport.
fn browser_tunnel_id() -> Result<String, JsValue> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| JsValue::from_str("browser random generator is unavailable"))?;
    Ok(hex_bytes(&random))
}

/// Yield to the browser between empty M5oH mailbox reads.  The timer stays in
/// Rust/WASM so application code cannot accidentally create an unbounded GET
/// loop while a router is still establishing an upstream connection.
async fn browser_sleep(delay_ms: i32) -> Result<(), JsValue> {
    let window = web_sys::window()
        .ok_or_else(|| JsValue::from_str("browser window is unavailable"))?;
    let promise = Promise::new(&mut move |resolve, reject| {
        let resolve = resolve.clone();
        let reject = reject.clone();
        let callback = Closure::once_into_js(move || {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        });
        let callback: &Function = callback.unchecked_ref();
        if let Err(error) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            callback,
            delay_ms.max(0),
        ) {
            let _ = reject.call1(&JsValue::UNDEFINED, &error);
        }
    });
    JsFuture::from(promise).await.map(|_| ())
}

async fn media_authenticate(session: &mut BrowserSession, ticket: String) -> Result<(), JsValue> {
    let result = session
        .request(
            MST5_KIND_AUTH,
            0,
            serde_json::json!({"mechanism": "media_ticket", "ticket": ticket}),
        )
        .await?;
    if result.0 {
        Ok(())
    } else {
        Err(JsValue::from_str(&format!(
            "MST5 media authentication failed: {}",
            result.1
        )))
    }
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

impl BrowserMediaUpload {
    async fn open(
        mut session: BrowserSession,
        file_id: String,
        expected_size: usize,
    ) -> Result<Self, JsValue> {
        Self::open_with_offset(session, file_id, expected_size, 0, None).await
    }

    async fn open_with_offset(
        mut session: BrowserSession,
        file_id: String,
        expected_size: usize,
        offset: usize,
        checksum: Option<String>,
    ) -> Result<Self, JsValue> {
        if offset > expected_size {
            return Err(JsValue::from_str("media upload offset exceeds size"));
        }
        let id = session.take_request_id()?;
        let mut open = serde_json::json!({"file_id": file_id, "size": expected_size, "offset": offset});
        if let Some(checksum) = checksum.as_deref() { open["sha256"] = JsonValue::String(checksum.to_owned()); }
        let payload = serde_cbor::to_vec(&open)
                .map_err(|_| JsValue::from_str("cannot encode media stream open"))?;
        session
            .write_frame(MST5_KIND_STREAM_OPEN, MEDIA_OP_UPLOAD, id, &payload)
            .await?;
        let accepted = session.read_matching_frame(id).await?;
        if accepted.kind != MST5_KIND_ACK || accepted.code != 100 {
            return Err(frame_error("media upload was rejected", &accepted));
        }
        let details: JsonValue = serde_cbor::from_slice(&accepted.payload)
            .map_err(|_| JsValue::from_str("invalid media upload acknowledgement"))?;
        let accepted_offset = details.get("offset").and_then(JsonValue::as_u64).unwrap_or(offset as u64);
        if accepted_offset != offset as u64 { return Err(JsValue::from_str("media node checkpoint mismatch")); }
        let server_chunk = details
            .get("chunk_size")
            .and_then(JsonValue::as_u64)
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size > 0)
            .ok_or_else(|| JsValue::from_str("media node did not provide a chunk size"))?;
        Ok(Self {
            session,
            id,
            expected_size,
            sent: offset,
            chunk_size: BROWSER_MEDIA_CHUNK.min(server_chunk),
            digest: Sha256::new(),
            resume_checksum: checksum,
        })
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), JsValue> {
        if self.sent.saturating_add(data.len()) > self.expected_size {
            return Err(JsValue::from_str("media source exceeds its declared size"));
        }
        for chunk in data.chunks(self.chunk_size) {
            self.digest.update(chunk);
            self.session
                .write_frame(MST5_KIND_STREAM_DATA, 0, self.id, chunk)
                .await?;
            self.sent += chunk.len();
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), JsValue> {
        if self.sent != self.expected_size {
            return Err(JsValue::from_str(
                "media source ended before its declared size",
            ));
        }
        let checksum = self.resume_checksum.clone().unwrap_or_else(|| hex_bytes(&self.digest.clone().finalize()));
        let end = serde_cbor::to_vec(&serde_json::json!({"size": self.sent, "sha256": checksum}))
            .map_err(|_| JsValue::from_str("cannot encode media stream end"))?;
        self.session
            .write_frame(MST5_KIND_STREAM_END, 200, self.id, &end)
            .await?;
        let result = self.session.read_matching_frame(self.id).await?;
        if result.kind != MST5_KIND_RESULT || !(200..300).contains(&result.code) {
            return Err(frame_error("media upload failed", &result));
        }
        Ok(())
    }

    async fn abort(&mut self) -> Result<(), JsValue> {
        self.session
            .write_frame(MST5_KIND_STREAM_ABORT, 499, self.id, &[])
            .await
    }
}

impl BrowserSession {
    async fn negotiate(&mut self, required_features: u64) -> Result<(), JsValue> {
        let payload = JsonValue::Object(JsonMap::from_iter([
            (
                "transport_major".to_owned(),
                JsonValue::from(TRANSPORT_MAJOR),
            ),
            ("rpc_major".to_owned(), JsonValue::from(RPC_MAJOR)),
            ("rpc_minor".to_owned(), JsonValue::from(RPC_MINOR)),
            ("features".to_owned(), JsonValue::from(required_features)),
            (
                "required_features".to_owned(),
                JsonValue::from(required_features),
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
                & required_features
                != required_features
        {
            return Err(JsValue::from_str(
                "MST5 SERVER_HELLO omitted required capabilities",
            ));
        }
        Ok(())
    }

    async fn upload_media(&mut self, file_id: &str, data: &[u8]) -> Result<(), JsValue> {
        let id = self.take_request_id()?;
        let payload =
            serde_cbor::to_vec(&serde_json::json!({"file_id": file_id, "size": data.len()}))
                .map_err(|_| JsValue::from_str("cannot encode media stream open"))?;
        self.write_frame(MST5_KIND_STREAM_OPEN, MEDIA_OP_UPLOAD, id, &payload)
            .await?;
        let accepted = self.read_matching_frame(id).await?;
        if accepted.kind != MST5_KIND_ACK || accepted.code != 100 {
            return Err(frame_error("media upload was rejected", &accepted));
        }
        let details: JsonValue = serde_cbor::from_slice(&accepted.payload)
            .map_err(|_| JsValue::from_str("invalid media upload acknowledgement"))?;
        let server_chunk = details
            .get("chunk_size")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as usize;
        if server_chunk == 0 {
            return Err(JsValue::from_str("media node did not provide a chunk size"));
        }
        let chunk = BROWSER_MEDIA_CHUNK.min(server_chunk);
        let mut digest = Sha256::new();
        for bytes in data.chunks(chunk) {
            digest.update(bytes);
            self.write_frame(MST5_KIND_STREAM_DATA, 0, id, bytes)
                .await?;
        }
        let checksum = hex_bytes(&digest.finalize());
        let end = serde_cbor::to_vec(&serde_json::json!({"size": data.len(), "sha256": checksum}))
            .map_err(|_| JsValue::from_str("cannot encode media stream end"))?;
        self.write_frame(MST5_KIND_STREAM_END, 200, id, &end)
            .await?;
        let result = self.read_matching_frame(id).await?;
        if result.kind != MST5_KIND_RESULT || !(200..300).contains(&result.code) {
            return Err(frame_error("media upload failed", &result));
        }
        Ok(())
    }

    async fn download_media(
        &mut self,
        file_id: &str,
        expected_size: usize,
    ) -> Result<Vec<u8>, JsValue> {
        let id = self.take_request_id()?;
        let payload = serde_cbor::to_vec(&serde_json::json!({"file_id": file_id}))
            .map_err(|_| JsValue::from_str("cannot encode media download open"))?;
        self.write_frame(MST5_KIND_STREAM_OPEN, MEDIA_OP_DOWNLOAD, id, &payload)
            .await?;
        let accepted = self.read_matching_frame(id).await?;
        if accepted.kind != MST5_KIND_ACK || accepted.code != 100 {
            return Err(frame_error("media download was rejected", &accepted));
        }
        let metadata: JsonValue = serde_cbor::from_slice(&accepted.payload)
            .map_err(|_| JsValue::from_str("invalid media download acknowledgement"))?;
        let announced = metadata
            .get("size")
            .and_then(JsonValue::as_u64)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| JsValue::from_str("media node omitted a valid file size"))?;
        if announced != expected_size {
            return Err(JsValue::from_str("media file size changed before download"));
        }

        let mut data = Vec::with_capacity(announced);
        let mut digest = Sha256::new();
        loop {
            let frame = self.read_matching_frame(id).await?;
            match frame.kind {
                MST5_KIND_STREAM_DATA => {
                    if frame.payload.is_empty()
                        || frame.payload.len() > BROWSER_MEDIA_CHUNK
                        || data.len().saturating_add(frame.payload.len()) > announced
                    {
                        return Err(JsValue::from_str("invalid MST5 media download chunk"));
                    }
                    digest.update(&frame.payload);
                    data.extend_from_slice(&frame.payload);
                }
                MST5_KIND_STREAM_END => {
                    let end: JsonValue = serde_cbor::from_slice(&frame.payload)
                        .map_err(|_| JsValue::from_str("invalid MST5 media download end"))?;
                    let checksum = hex_bytes(&digest.finalize());
                    if data.len() != announced
                        || end.get("size").and_then(JsonValue::as_u64) != Some(data.len() as u64)
                        || end.get("sha256").and_then(JsonValue::as_str) != Some(checksum.as_str())
                    {
                        return Err(JsValue::from_str("MST5 media download checksum mismatch"));
                    }
                    return Ok(data);
                }
                MST5_KIND_ERROR => return Err(frame_error("media download failed", &frame)),
                _ => return Err(JsValue::from_str("unexpected MST5 media download frame")),
            }
        }
    }

    async fn download_media_stream(&mut self, file_id: &str, expected_size: usize, on_chunk: &Function) -> Result<(), JsValue> {
        let id = self.take_request_id()?;
        let payload = serde_cbor::to_vec(&serde_json::json!({"file_id": file_id})).map_err(|_| JsValue::from_str("cannot encode media download open"))?;
        self.write_frame(MST5_KIND_STREAM_OPEN, MEDIA_OP_DOWNLOAD, id, &payload).await?;
        let accepted = self.read_matching_frame(id).await?;
        if accepted.kind != MST5_KIND_ACK || accepted.code != 100 { return Err(frame_error("media download was rejected", &accepted)); }
        let metadata: JsonValue = serde_cbor::from_slice(&accepted.payload).map_err(|_| JsValue::from_str("invalid media download acknowledgement"))?;
        let announced = metadata.get("size").and_then(JsonValue::as_u64).and_then(|size| usize::try_from(size).ok()).ok_or_else(|| JsValue::from_str("media node omitted a valid file size"))?;
        if announced != expected_size { return Err(JsValue::from_str("media file size changed before download")); }
        let mut received = 0usize; let mut digest = Sha256::new();
        loop {
            let frame = self.read_matching_frame(id).await?;
            match frame.kind {
                MST5_KIND_STREAM_DATA => {
                    if frame.payload.is_empty() || frame.payload.len() > BROWSER_MEDIA_CHUNK || received.saturating_add(frame.payload.len()) > announced { return Err(JsValue::from_str("invalid MST5 media download chunk")); }
                    digest.update(&frame.payload); received += frame.payload.len();
                    let chunk = Uint8Array::from(frame.payload.as_slice()); on_chunk.call1(&JsValue::UNDEFINED, &chunk.into())?;
                }
                MST5_KIND_STREAM_END => {
                    let end: JsonValue = serde_cbor::from_slice(&frame.payload).map_err(|_| JsValue::from_str("invalid MST5 media download end"))?;
                    let checksum = hex_bytes(&digest.finalize());
                    if received != announced || end.get("size").and_then(JsonValue::as_u64) != Some(received as u64) || end.get("sha256").and_then(JsonValue::as_str) != Some(checksum.as_str()) { return Err(JsValue::from_str("MST5 media download checksum mismatch")); }
                    return Ok(());
                }
                MST5_KIND_ERROR => return Err(frame_error("media download failed", &frame)),
                _ => return Err(JsValue::from_str("unexpected MST5 media download frame")),
            }
        }
    }

    async fn download_e2e_media(
        &mut self,
        file_id: &str,
        expected_size: usize,
        mut decryptor: e2e::MediaDecryptor,
    ) -> Result<Vec<u8>, JsValue> {
        let id = self.take_request_id()?;
        let payload = serde_cbor::to_vec(&serde_json::json!({"file_id": file_id}))
            .map_err(|_| JsValue::from_str("cannot encode media download open"))?;
        self.write_frame(MST5_KIND_STREAM_OPEN, MEDIA_OP_DOWNLOAD, id, &payload)
            .await?;
        let accepted = self.read_matching_frame(id).await?;
        if accepted.kind != MST5_KIND_ACK || accepted.code != 100 {
            return Err(frame_error("media download was rejected", &accepted));
        }
        let metadata: JsonValue = serde_cbor::from_slice(&accepted.payload)
            .map_err(|_| JsValue::from_str("invalid media download acknowledgement"))?;
        let announced = metadata
            .get("size")
            .and_then(JsonValue::as_u64)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| JsValue::from_str("media node omitted a valid file size"))?;
        if announced != expected_size {
            return Err(JsValue::from_str("media file size changed before download"));
        }

        let mut ciphertext_size = 0usize;
        let mut plaintext = Vec::with_capacity(announced);
        let mut digest = Sha256::new();
        loop {
            let frame = self.read_matching_frame(id).await?;
            match frame.kind {
                MST5_KIND_STREAM_DATA => {
                    if frame.payload.is_empty()
                        || frame.payload.len() > BROWSER_MEDIA_CHUNK
                        || ciphertext_size.saturating_add(frame.payload.len()) > announced
                    {
                        return Err(JsValue::from_str("invalid MST5 media download chunk"));
                    }
                    digest.update(&frame.payload);
                    ciphertext_size += frame.payload.len();
                    for mut chunk in decryptor.push(&frame.payload).map_err(e2e_error)? {
                        plaintext.append(&mut chunk);
                    }
                }
                MST5_KIND_STREAM_END => {
                    let end: JsonValue = serde_cbor::from_slice(&frame.payload)
                        .map_err(|_| JsValue::from_str("invalid media download end"))?;
                    let checksum = hex_bytes(&digest.finalize());
                    if ciphertext_size != announced
                        || end.get("size").and_then(JsonValue::as_u64)
                            != Some(ciphertext_size as u64)
                        || end.get("sha256").and_then(JsonValue::as_str)
                            != Some(checksum.as_str())
                    {
                        return Err(JsValue::from_str("MST5 media download checksum mismatch"));
                    }
                    let recovered = decryptor.finish().map_err(e2e_error)?;
                    if plaintext.len() as u64 != recovered {
                        return Err(JsValue::from_str("E2E media size mismatch"));
                    }
                    return Ok(plaintext);
                }
                MST5_KIND_ERROR => return Err(frame_error("media download failed", &frame)),
                _ => return Err(JsValue::from_str("unexpected MST5 media download frame")),
            }
        }
    }

    fn take_request_id(&mut self) -> Result<u64, JsValue> {
        let id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("MST5 request id exhausted"))?;
        Ok(id)
    }

    async fn write_frame(
        &mut self,
        kind: u8,
        code: u16,
        id: u64,
        payload: &[u8],
    ) -> Result<(), JsValue> {
        let frame = frame_encode(kind, code, id, payload)?;
        self.write_record(&frame).await
    }

    async fn read_matching_frame(&mut self, id: u64) -> Result<Frame, JsValue> {
        loop {
            let frame = frame_decode(&self.read_record().await?)?;
            if frame.id == id {
                return Ok(frame);
            }
        }
    }

    async fn request(
        &mut self,
        kind: u8,
        code: u16,
        body: JsonValue,
    ) -> Result<(bool, String, JsonValue), JsValue> {
        let id = if kind == MST5_KIND_HELLO {
            0
        } else {
            self.take_request_id()?
        };
        let payload = serde_cbor::to_vec(&body)
            .map_err(|_| JsValue::from_str("cannot encode MST5 command"))?;
        self.write_frame(kind, code, id, &payload).await?;
        let decoded = self.read_matching_frame(id).await?;
        let value: JsonValue = serde_cbor::from_slice(&decoded.payload)
            .map_err(|_| JsValue::from_str("invalid CBOR response"))?;
        let ok = successful_response(kind, decoded.kind, decoded.code);
        let reason = value
            .get("message")
            .and_then(JsonValue::as_str)
            .unwrap_or("MST5 request failed")
            .to_owned();
        Ok((ok, reason, value))
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
        let mut empty_delay_ms = M5OH_EMPTY_POLL_INITIAL_MS;
        while self.received.len() < length {
            let bytes = self
                .transport
                .downstream_bytes(&self.tunnel_id, self.downstream_seq)
                .await?;
            self.downstream_seq = self
                .downstream_seq
                .checked_add(1)
                .ok_or_else(|| JsValue::from_str("M5oH download sequence exhausted"))?;
            if bytes.is_empty() {
                browser_sleep(empty_delay_ms).await?;
                empty_delay_ms = empty_delay_ms
                    .saturating_mul(2)
                    .min(M5OH_EMPTY_POLL_MAX_MS);
                continue;
            }
            empty_delay_ms = M5OH_EMPTY_POLL_INITIAL_MS;
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
    let mut empty_delay_ms = M5OH_EMPTY_POLL_INITIAL_MS;
    while received.len() < 54 {
        let body = transport.downstream_bytes(&tunnel_id, down).await?;
        down += 1;
        if body.is_empty() {
            browser_sleep(empty_delay_ms).await?;
            empty_delay_ms = empty_delay_ms
                .saturating_mul(2)
                .min(M5OH_EMPTY_POLL_MAX_MS);
            continue;
        }
        empty_delay_ms = M5OH_EMPTY_POLL_INITIAL_MS;
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
    if input.len() < 40 {
        return Err(JsValue::from_str("invalid MST5 frame"));
    }
    let flags = input[1];
    if flags & !MST5_FLAG_DEFLATE != 0 {
        return Err(JsValue::from_str("unsupported MST5 frame compression"));
    }
    let size = u32::from_be_bytes(
        input[36..40]
            .try_into()
            .map_err(|_| JsValue::from_str("invalid MST5 frame size"))?,
    ) as usize;
    if input.len() != 40 + size {
        return Err(JsValue::from_str("invalid MST5 frame size"));
    }
    let payload = if flags == MST5_FLAG_DEFLATE {
        let decoder = DeflateDecoder::new(&input[40..]);
        let mut output = Vec::new();
        decoder
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| JsValue::from_str("invalid MST5 deflate payload"))?;
        if output.len() > MAX_RECORD_BYTES {
            return Err(JsValue::from_str(
                "MST5 deflate payload exceeds the frame limit",
            ));
        }
        output
    } else {
        input[40..].to_vec()
    };
    Ok(Frame {
        kind: input[0],
        code: u16::from_be_bytes([input[2], input[3]]),
        id: u64::from_be_bytes(
            input[4..12]
                .try_into()
                .map_err(|_| JsValue::from_str("invalid MST5 frame id"))?,
        ),
        payload,
    })
}

fn successful_response(request_kind: u8, response_kind: u8, code: u16) -> bool {
    // HELLO is acknowledged with another HELLO frame; all remaining request
    // types use RESULT. Treating negotiation as RESULT made valid browser
    // M5oHS sessions fail before authentication.
    let expected_kind = if request_kind == 11 { 11 } else { 4 };
    response_kind == expected_kind && (200..300).contains(&code)
}

fn frame_error(context: &str, frame: &Frame) -> JsValue {
    let message = serde_cbor::from_slice::<JsonValue>(&frame.payload)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("MST5 status {}", frame.code));
    JsValue::from_str(&format!("{context}: {message}"))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

/// Browser media endpoints retain the native endpoint first and append a
/// router fallback (`mst5://…|http(s)://router/IPv4:port`).  Deliberately
/// consume only the fallback path; a web page must never attempt the raw TCP
/// endpoint or expose it as a fetch target.
fn parse_media_destination(value: &str) -> Result<String, JsValue> {
    let fallback = value
        .split('|')
        .map(str::trim)
        .find(|item| item.starts_with("http://") || item.starts_with("https://"))
        .ok_or_else(|| JsValue::from_str("media node has no browser M5oH endpoint"))?;
    let after_scheme = fallback
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| JsValue::from_str("invalid browser media endpoint"))?;
    let (_, path) = after_scheme
        .split_once('/')
        .ok_or_else(|| JsValue::from_str("browser media endpoint lacks a destination"))?;
    let destination = path.split(['/', '?', '#']).next().unwrap_or_default();
    let (ip, port) = parse_destination(destination)?;
    if ip.split('.').count() != 4 || ip.split('.').any(|part| part.parse::<u8>().is_err()) {
        return Err(JsValue::from_str("browser media destination must be IPv4"));
    }
    Ok(format!("{ip}:{port}"))
}

// Keep this ABI mapping in the SDK boundary. Web UI code uses paths only,
// matching the native MessengerCore JSON contract.
fn operation(method: &str, path: &str) -> Result<u16, JsValue> {
    let code = match (method, path) {
        ("POST", "/register") => 1,
        ("POST", "/login") => 2,
        ("POST", "/auth/email/start") => 3,
        ("POST", "/auth/email/verify") => 4,
        ("POST", "/auth/qr/start") => 98,
        ("GET", "/auth/qr/poll") => 99,
        ("POST", "/auth/qr/approve") => 100,
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
        ("GET", "/nodes/status") => 50,
        ("GET", "/chats") => 51,
        ("POST", "/chats/delete") => 52,
        ("POST", "/users/ban") => 53,
        ("POST", "/users/unban") => 54,
        ("GET", "/history") => 55,
        ("GET", "/updates") => 56,
        ("GET", "/oauth/device/request") => 60,
        ("POST", "/oauth/device/decision") => 61,
        ("GET", "/file/ticket") => 65,
        ("POST", "/forward") => 69,
        ("POST", "/media/quote") => 70,
        ("POST", "/messages/prepare") => 71,
        ("POST", "/messages/commit") => 72,
        ("POST", "/messages/cancel") => 73,
        ("POST", "/pin") => 92,
        ("POST", "/polls/vote") => 93,
        ("GET", "/chats/favorites") => 94,
        ("POST", "/chats/favorite") => 95,
        ("GET", "/chats/folders") => 96,
        ("POST", "/chats/folder") => 97,
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
            // M5oH carries its opaque route selector at the start of every
            // GET payload. This is the same packet format as the native
            // clients and lets requests be routed independently of HTTP
            // headers while keeping the destination unreadable in the URL.
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
        // The GET-only router uses a tiny `OK` body to keep an empty
        // long-poll response cacheable/replayable.  The accompanying status
        // header makes it control data, not bytes from the encrypted TCP
        // stream.  Treating that body as RSP5 caused an intermittent
        // "invalid MST5 server hello" on a freshly opened browser tunnel.
        if response.headers().get(HEADER_STATUS)?.as_deref() == Some("OK") {
            return Ok(Uint8Array::new_with_length(0));
        }
        let body = JsFuture::from(response.array_buffer()?).await?;
        Ok(Uint8Array::new(&body))
    }
}
