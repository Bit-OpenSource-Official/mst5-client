//! Messenger-specific core built on top of the transport-level [`AccountClient`].
//!
//! Android, desktop and future clients use this module through a deliberately
//! small JSON command boundary.  The UI never selects a wire transport, maps
//! REST-era paths to MST5 opcodes, or encodes CBOR: those are protocol concerns
//! and belong next to the MST5 implementation.

use crate::{kind, op, AccountClient, AccountConfig, RequestOptions, Value};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// User-visible transport preference.  `Auto` always attempts native MST5
/// candidates before M5oH candidates, regardless of their order in config.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    #[default]
    Auto,
    Mst5,
    M5oh,
}

impl TransportMode {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "mst5" => Self::Mst5,
            "m5oh" | "m5ohs" => Self::M5oh,
            _ => Self::Auto,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Mst5 => "mst5",
            Self::M5oh => "m5oh",
        }
    }
}

/// Resolves a configured endpoint chain without exposing transport policy to a
/// UI.  A forced mode is strict: silently falling through to another protocol
/// would make the setting misleading and can defeat a network policy.
pub fn select_endpoint(configured: &str, mode: TransportMode) -> io::Result<String> {
    let candidates: Vec<&str> = configured
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    if candidates.is_empty() {
        return Err(invalid_input("MST5 endpoint list is empty"));
    }

    let is_m5oh = |value: &&str| {
        let lower = value.to_ascii_lowercase();
        lower.starts_with("m5oh://") || lower.starts_with("m5ohs://")
    };
    let selected: Vec<&str> = match mode {
        TransportMode::Auto => candidates
            .iter()
            .filter(|candidate| !is_m5oh(candidate))
            .chain(candidates.iter().filter(|candidate| is_m5oh(candidate)))
            .copied()
            .collect(),
        TransportMode::Mst5 => candidates
            .iter()
            .filter(|candidate| !is_m5oh(candidate))
            .copied()
            .collect(),
        TransportMode::M5oh => candidates
            .iter()
            .filter(|candidate| is_m5oh(candidate))
            .copied()
            .collect(),
    };
    if selected.is_empty() {
        return Err(invalid_input(match mode {
            TransportMode::Auto => "MST5 endpoint list is empty",
            TransportMode::Mst5 => "no MST5 endpoint is configured",
            TransportMode::M5oh => "no M5oH endpoint is configured",
        }));
    }
    Ok(selected.join("|"))
}

#[derive(Clone, Debug)]
pub struct MessengerConfig {
    /// The stable, user-configured endpoint chain.  It may contain different
    /// hosts for MST5 and M5oH.
    pub endpoint: String,
    pub pinned_public_key_b64: String,
    pub device_model: String,
    pub transport_mode: TransportMode,
    pub client_name: String,
}

impl MessengerConfig {
    pub fn new(
        endpoint: impl Into<String>,
        pinned_public_key_b64: impl Into<String>,
        device_model: impl Into<String>,
        transport_mode: TransportMode,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            pinned_public_key_b64: pinned_public_key_b64.into(),
            device_model: device_model.into(),
            transport_mode,
            client_name: "OVE.rs Android".to_string(),
        }
    }
}

/// Stateless-looking command core.  It intentionally owns the account
/// connection and protocol serialization; callers only exchange JSON values.
#[derive(Clone)]
pub struct MessengerCore {
    account: AccountClient,
    endpoint: String,
    transport_mode: TransportMode,
}

impl MessengerCore {
    pub fn new(config: MessengerConfig) -> io::Result<Self> {
        let endpoint = select_endpoint(&config.endpoint, config.transport_mode)?;
        let mut account_config = AccountConfig::new(
            endpoint.clone(),
            config.pinned_public_key_b64,
            "",
            config.client_name,
        )
        .with_device_model(config.device_model);
        account_config.options.read_timeout = Duration::from_secs(120);
        account_config.options.write_timeout = Duration::from_secs(30);
        Ok(Self {
            account: AccountClient::new(account_config)?,
            endpoint,
            transport_mode: config.transport_mode,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn transport_mode(&self) -> TransportMode {
        self.transport_mode
    }

    pub async fn close(&self) -> io::Result<()> {
        self.account.close().await
    }

    /// Compatibility path for the old byte-buffer JNI entry point.  New
    /// clients should use [`Self::command_json`].
    pub async fn request_cbor(
        &self,
        token: &str,
        frame_kind: u8,
        opcode: u16,
        payload: &[u8],
        options: RequestOptions,
    ) -> io::Result<crate::Response> {
        self.account
            .set_credentials(token, "OVE.rs Android")
            .await?;
        self.account
            .request_cbor(frame_kind, opcode, payload, options)
            .await
    }

    /// Executes a JSON command and returns a JSON response:
    ///
    /// ```json
    /// {"token":"…","method":"GET","path":"/me","body":{},"timeout_ms":10000}
    /// ```
    ///
    /// The wire payload remains canonical CBOR and the REST-like path is only
    /// an ABI convenience.  Routing is mapped to the typed MST5 opcode here,
    /// never in managed UI code.
    pub async fn command_json(&self, source: &str) -> io::Result<String> {
        let input: JsonValue = serde_json::from_str(source)
            .map_err(|error| invalid_input(format!("invalid messenger JSON command: {error}")))?;
        let object = input
            .as_object()
            .ok_or_else(|| invalid_input("messenger JSON command must be an object"))?;
        let token = string_field(object, "token")?;
        let method = string_field_or(object, "method", "GET").to_ascii_uppercase();
        let raw_path = string_field_or(object, "path", "/");
        let timeout_ms = object
            .get("timeout_ms")
            .and_then(JsonValue::as_u64)
            .unwrap_or(10_000)
            .clamp(1, 120_000);
        let (path, query) = split_query(&raw_path);
        let opcode = operation(&method, path)?;
        let frame_kind = if method == "GET" {
            kind::QUERY
        } else {
            kind::COMMAND
        };
        let payload_json = if method == "GET" {
            match query {
                Some(value) if !value.is_empty() => json!({ "query": value }),
                _ => JsonValue::Object(JsonMap::new()),
            }
        } else {
            object
                .get("body")
                .cloned()
                .unwrap_or_else(|| JsonValue::Object(JsonMap::new()))
        };
        let payload = json_to_cbor(&payload_json)?.encode_cbor();
        let deadline_ms = unix_now_ms().saturating_add(timeout_ms);
        let response = self
            .request_cbor(
                &token,
                frame_kind,
                opcode,
                &payload,
                RequestOptions::default().with_deadline_ms(deadline_ms),
            )
            .await?;
        let body = Value::decode_cbor(&response.payload)
            .map_err(|error| invalid_data(format!("invalid MST5 CBOR response: {error}")))?;
        serde_json::to_string(&json!({
            "kind": response.kind,
            "code": response.status,
            "body": cbor_to_json(&body),
        }))
        .map_err(|error| {
            io::Error::other(format!("cannot encode messenger JSON response: {error}"))
        })
    }
}

fn split_query(path: &str) -> (&str, Option<&str>) {
    match path.find('?') {
        Some(index) => (&path[..index], Some(&path[index + 1..])),
        None => (path, None),
    }
}

fn string_field(object: &JsonMap<String, JsonValue>, key: &str) -> io::Result<String> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_input(format!("messenger JSON command is missing string {key}")))
}

fn string_field_or(object: &JsonMap<String, JsonValue>, key: &str, fallback: &str) -> String {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or(fallback)
        .to_string()
}

fn json_to_cbor(value: &JsonValue) -> io::Result<Value> {
    Ok(match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => json_number_to_cbor(value)?,
        JsonValue::String(value) => Value::Text(value.clone()),
        JsonValue::Array(values) => Value::Array(
            values
                .iter()
                .map(json_to_cbor)
                .collect::<io::Result<Vec<_>>>()?,
        ),
        JsonValue::Object(values) => Value::Map(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), json_to_cbor(value)?)))
                .collect::<io::Result<Vec<_>>>()?,
        ),
    })
}

fn json_number_to_cbor(value: &JsonNumber) -> io::Result<Value> {
    if let Some(value) = value.as_u64() {
        return Ok(Value::Unsigned(value));
    }
    if let Some(value) = value.as_i64() {
        return Ok(Value::Integer(value));
    }
    value
        .as_f64()
        .filter(|value| value.is_finite())
        .map(Value::Float)
        .ok_or_else(|| invalid_input("messenger JSON contains a non-finite number"))
}

fn cbor_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Bool(value) => JsonValue::Bool(*value),
        Value::Unsigned(value) => JsonValue::Number(JsonNumber::from(*value)),
        Value::Integer(value) => JsonValue::Number(JsonNumber::from(*value)),
        Value::Float(value) => JsonNumber::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        // Keep the wire-compatible Android representation: CBOR byte strings
        // have historically been exposed to MiniTaLib as JSON byte arrays.
        Value::Bytes(values) => JsonValue::Array(
            values
                .iter()
                .map(|value| JsonValue::Number(JsonNumber::from(*value)))
                .collect(),
        ),
        Value::Text(value) => JsonValue::String(value.clone()),
        Value::Array(values) => JsonValue::Array(values.iter().map(cbor_to_json).collect()),
        Value::Map(values) => JsonValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), cbor_to_json(value)))
                .collect(),
        ),
    }
}

fn operation(method: &str, path: &str) -> io::Result<u16> {
    let operation = match (method, path) {
        ("POST", "/register") => op::REGISTER,
        ("POST", "/login") => op::LOGIN,
        ("POST", "/auth/email/start") => op::EMAIL_AUTH_START,
        ("POST", "/auth/email/verify") => op::EMAIL_AUTH_VERIFY,
        ("GET", "/me") => op::ME,
        ("POST", "/account/delete") => op::ACCOUNT_DELETE,
        ("POST", "/username") => op::SET_USERNAME,
        ("POST", "/name") => op::SET_NAME,
        ("POST", "/privacy") => op::SET_PRIVACY,
        ("GET", "/contacts") => op::CONTACTS,
        ("POST", "/contacts/add") => op::CONTACT_ADD,
        ("POST", "/contacts/delete") => op::CONTACT_DELETE,
        ("POST", "/groups") => op::CREATE_GROUP,
        ("POST", "/channels") => op::CREATE_CHANNEL,
        ("POST", "/chats/title") => op::SET_CHAT_TITLE,
        ("POST", "/channels/username") => op::SET_CHANNEL_USERNAME,
        ("POST", "/channels/comments/settings") => op::SET_CHANNEL_COMMENTS,
        ("POST", "/channels/comments/send") => op::SEND_CHANNEL_COMMENT,
        ("GET", "/channels/comments") => op::CHANNEL_COMMENTS,
        ("POST", "/chats/members/add") => op::ADD_CHAT_MEMBER,
        ("POST", "/chats/members/remove") => op::REMOVE_CHAT_MEMBER,
        ("POST", "/cloud-password") => op::SET_CLOUD_PASSWORD,
        ("POST", "/cloud-password/reset") => op::RESET_CLOUD_PASSWORD,
        ("GET", "/sessions") => op::SESSIONS,
        ("POST", "/sessions/revoke") => op::REVOKE_SESSION,
        ("POST", "/sessions/revoke-others") => op::REVOKE_OTHER_SESSIONS,
        ("POST", "/bots") => op::CREATE_BOT,
        ("POST", "/bots/token/reset") => op::RESET_BOT_TOKEN,
        ("GET", "/bots/commands") => op::BOT_COMMANDS,
        ("GET", "/stickers/packs") => op::STICKER_PACKS,
        ("GET", "/stickers/pack") => op::STICKER_PACK,
        ("POST", "/stickers/packs") => op::STICKER_CREATE,
        ("POST", "/stickers/packs/purchase") => op::STICKER_PURCHASE,
        ("POST", "/stickers/send") => op::STICKER_SEND,
        ("POST", "/stickers/packs/price") => op::STICKER_PRICE,
        ("POST", "/e2e/key") => op::SET_E2E_KEY,
        ("GET", "/e2e/key") => op::GET_E2E_KEY,
        ("POST", "/e2e/backup") => op::SET_E2E_BACKUP,
        ("GET", "/e2e/backup") => op::GET_E2E_BACKUP,
        ("POST", "/e2e/reset") => op::RESET_E2E,
        ("GET", "/wallet") => op::WALLET,
        ("POST", "/wallet/send") => op::WALLET_SEND,
        ("GET", "/wallet/history") => op::WALLET_HISTORY,
        ("POST", "/call") => op::CALL,
        ("POST", "/voice-ticket") => op::VOICE_TICKET,
        ("GET", "/voice/participants") => op::VOICE_PARTICIPANTS,
        ("POST", "/send") => op::SEND,
        ("POST", "/edit") => op::EDIT,
        ("POST", "/callback") => op::CALLBACK,
        ("POST", "/reactions") => op::REACT,
        ("POST", "/reactions/paid") => op::REACT_PAID,
        ("POST", "/read") => op::READ,
        ("POST", "/delete") => op::DELETE,
        ("POST", "/favorite") => op::FAVORITE,
        ("GET", "/nodes/status") => op::NODES_STATUS,
        ("GET", "/chats") => op::CHATS,
        ("POST", "/chats/delete") => op::DELETE_CHAT,
        ("POST", "/users/ban") => op::BAN_USER,
        ("POST", "/users/unban") => op::UNBAN_USER,
        ("GET", "/history") => op::HISTORY,
        ("GET", "/updates") => op::SYNC,
        ("GET", "/oauth/device/request") => op::OAUTH_DEVICE_REQUEST,
        ("POST", "/oauth/device/decision") => op::OAUTH_DEVICE_DECISION,
        ("GET", "/file/ticket") => op::FILE_TICKET,
        ("POST", "/forward") => op::FORWARD,
        ("POST", "/media/quote") => op::MEDIA_QUOTE,
        ("POST", "/messages/prepare") => op::MESSAGE_PREPARE,
        ("POST", "/messages/commit") => op::MESSAGE_COMMIT,
        ("POST", "/messages/cancel") => op::MESSAGE_CANCEL,
        ("POST", "/avatars/prepare") => op::AVATAR_PREPARE,
        ("POST", "/avatars/commit") => op::AVATAR_COMMIT,
        ("POST", "/avatars/delete") => op::AVATAR_DELETE,
        ("POST", "/profiles/description") => op::SET_PROFILE_DESCRIPTION,
        _ => {
            return Err(invalid_input(format!(
                "unsupported MST5 operation {method} {path}"
            )))
        }
    };
    Ok(operation)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

const SESSION_FILE: &str = "mst5-messenger-session-v1.json";
const SESSION_VERSION: u8 = 1;
const MAX_SESSION_BYTES: usize = 1024 * 1024;
const MAX_SESSION_KEY_CHARS: usize = 256;
const MAX_SESSION_VALUE_BYTES: usize = 256 * 1024;

/// Persistent, application-private state for a messenger core.  It is kept in
/// Rust so a UI can be replaced without changing token, sync cursor, transport
/// preference, or E2E peer-pin lifetime.  Android imports its old Java
/// properties file once through this store.
pub struct SessionStorage {
    path: PathBuf,
    values: BTreeMap<String, String>,
    exists: bool,
}

#[derive(Deserialize, Serialize)]
struct SessionDocument {
    version: u8,
    values: BTreeMap<String, String>,
}

impl SessionStorage {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref();
        if root.as_os_str().is_empty() {
            return Err(invalid_input("messenger session storage root is empty"));
        }
        fs::create_dir_all(root)?;
        let path = root.join(SESSION_FILE);
        if !path.exists() {
            return Ok(Self {
                path,
                values: BTreeMap::new(),
                exists: false,
            });
        }
        let raw = fs::read(&path)?;
        if raw.len() > MAX_SESSION_BYTES {
            return Err(invalid_data("messenger session file exceeds size limit"));
        }
        let document: SessionDocument = serde_json::from_slice(&raw)
            .map_err(|error| invalid_data(format!("invalid messenger session file: {error}")))?;
        if document.version != SESSION_VERSION {
            return Err(invalid_data("unsupported messenger session file version"));
        }
        validate_session_values(&document.values)?;
        Ok(Self {
            path,
            values: document.values,
            exists: true,
        })
    }

    /// A stable JSON ABI for platform adapters.  `exists` distinguishes a
    /// fresh install from an intentionally empty session after logout.
    pub fn snapshot_json(&self) -> io::Result<String> {
        serde_json::to_string(&json!({
            "version": SESSION_VERSION,
            "exists": self.exists,
            "values": self.values,
        }))
        .map_err(|error| io::Error::other(format!("cannot encode session snapshot: {error}")))
    }

    /// Replaces state atomically from a JSON string map.  A platform adapter
    /// never manipulates the backing file or token contents directly.
    pub fn replace_json(&mut self, raw: &str) -> io::Result<()> {
        let values: BTreeMap<String, String> = serde_json::from_str(raw)
            .map_err(|error| invalid_input(format!("invalid messenger session JSON: {error}")))?;
        validate_session_values(&values)?;
        let document = SessionDocument {
            version: SESSION_VERSION,
            values: values.clone(),
        };
        let encoded = serde_json::to_vec(&document).map_err(|error| {
            io::Error::other(format!("cannot encode messenger session: {error}"))
        })?;
        if encoded.len() > MAX_SESSION_BYTES {
            return Err(invalid_input("messenger session exceeds size limit"));
        }
        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, encoded)?;
        fs::rename(&temporary, &self.path)?;
        self.values = values;
        self.exists = true;
        Ok(())
    }
}

fn validate_session_values(values: &BTreeMap<String, String>) -> io::Result<()> {
    for (key, value) in values {
        if key.is_empty()
            || key.chars().count() > MAX_SESSION_KEY_CHARS
            || key.chars().any(|character| character.is_control())
        {
            return Err(invalid_input("invalid messenger session key"));
        }
        if value.len() > MAX_SESSION_VALUE_BYTES || value.contains('\0') {
            return Err(invalid_input("invalid messenger session value"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = "m5oh://cdn.example/main|mst5://central.example:8067/main";

    #[test]
    fn auto_always_prefers_mst5() {
        assert_eq!(
            select_endpoint(CHAIN, TransportMode::Auto).unwrap(),
            "mst5://central.example:8067/main|m5oh://cdn.example/main"
        );
    }

    #[test]
    fn forced_transport_does_not_fall_back() {
        assert_eq!(
            select_endpoint(CHAIN, TransportMode::M5oh).unwrap(),
            "m5oh://cdn.example/main"
        );
        assert!(select_endpoint("mst5://central.example:8067/main", TransportMode::M5oh).is_err());
    }

    #[test]
    fn json_boundary_matches_the_legacy_get_payload() {
        let command: JsonValue = serde_json::from_str(
            r#"{"token":"t","method":"GET","path":"/history?chat=alice&limit=20"}"#,
        )
        .unwrap();
        let raw_path = command["path"].as_str().unwrap();
        let (path, query) = split_query(raw_path);
        assert_eq!(operation("GET", path).unwrap(), op::HISTORY);
        assert_eq!(
            json_to_cbor(&json!({"query": query.unwrap()})).unwrap(),
            Value::map([("query", Value::from("chat=alice&limit=20"))])
        );
    }

    #[test]
    fn bytes_keep_android_json_shape() {
        assert_eq!(
            cbor_to_json(&Value::Bytes(vec![0, 127, 255])),
            json!([0, 127, 255])
        );
    }

    #[test]
    fn persistent_session_is_atomic_and_round_trips() {
        let root = std::env::temp_dir().join(format!(
            "mst5-session-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = SessionStorage::open(&root).unwrap();
        assert!(store.snapshot_json().unwrap().contains("\"exists\":false"));
        store
            .replace_json(r#"{"token":"saved-token","transport_protocol":"m5oh"}"#)
            .unwrap();
        let reopened = SessionStorage::open(&root).unwrap();
        let snapshot: JsonValue = serde_json::from_str(&reopened.snapshot_json().unwrap()).unwrap();
        assert_eq!(snapshot["values"]["token"], "saved-token");
        assert_eq!(snapshot["values"]["transport_protocol"], "m5oh");
        std::fs::remove_dir_all(root).unwrap();
    }
}
