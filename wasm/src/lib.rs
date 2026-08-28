//! Browser-only HTTP transport used by the MST5 web bindings.
//!
//! This crate deliberately owns only the browser boundary: opaque M5oH route
//! encoding and authenticated `fetch` requests.  Cipher state, records and
//! messenger operations remain in `mst5-client`; exposing a raw TCP-like
//! socket to JavaScript would leak protocol responsibilities into the UI.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use js_sys::Uint8Array;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, Response};

const USER_AGENT: &str = "OVE-MST5-M5oH/1";
const HEADER_SESSION: &str = "X-MST5-Session";
const HEADER_CHANNEL: &str = "X-MST5-Channel";
const HEADER_SEQUENCE: &str = "X-MST5-Seq";
const HEADER_EOF: &str = "X-MST5-EOF";
const MAX_GET_BYTES: usize = 23 * 1024 - 8;

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

impl M5ohFetch {
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
