use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroize;

mod account;
mod connection;
pub use mst5_e2e_core as e2e;
pub mod image;
mod m5oh;
pub mod messenger;
pub mod outbox;
pub use account::{AccountClient, AccountConfig, AccountEvent, AccountEventReceiver};
use connection::Mst5Connection;

/// Production server pin embedded by the build through
/// `CRYPT_SERVER_PUBLIC_KEY_B64`, when configured.
///
/// The value is a public key, not a private credential. It remains extractable
/// from a distributed native library even though it is supplied through CI
/// secrets rather than committed to source control.
pub const COMPILED_SERVER_PUBLIC_KEY_B64: Option<&str> = option_env!("CRYPT_SERVER_PUBLIC_KEY_B64");

pub fn compiled_server_public_key_b64() -> io::Result<&'static str> {
    COMPILED_SERVER_PUBLIC_KEY_B64
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "mst5-client was built without CRYPT_SERVER_PUBLIC_KEY_B64",
            )
        })
}

const CLIENT_MAGIC: &[u8; 4] = b"RCP5";
const SERVER_MAGIC: &[u8; 4] = b"RSP5";
const ROUTER_MAGIC: &[u8; 4] = b"M5RT";
const ROUTER_VERSION: u8 = 1;
const HANDSHAKE_MESSAGE_LEN: usize = 48;
const TAG_LEN: usize = 16;
const MAX_TRANSPORT_PAYLOAD: usize = 20 * 1024 * 1024;
const PADDING_BLOCK: usize = 256;
const LARGE_PADDING_BLOCK: usize = 128;
const LARGE_PADDING_THRESHOLD: usize = 1024;
const MAX_RECORDS: u64 = 1 << 20;
const MAX_PLAINTEXT_BYTES: u64 = 1 << 30;
const REKEY_RECORDS: u64 = 1 << 18;
const REKEY_BYTES: u64 = 256 << 20;
const PROTOCOL_NAME: &[u8] = b"Noise_NK_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"MicroMsg Secure Transport v5\0RCP5\0RSP5";
const RECORD_LABEL: &[u8] = b"MST5 record";
const MST5_HEADER_LEN: usize = 40;
const MST5_MAX_WIRE_PAYLOAD: usize = 4 * 1024 * 1024;
const MST5_MAX_PLAIN_PAYLOAD: usize = 4 * 1024 * 1024;
const MST5_FLAG_DEFLATE: u8 = 1;
const MST5_FLAG_ZSTD: u8 = 1 << 1;
const MST5_MAX_COMPRESSION_RATIO: usize = 64;
const TRANSPORT_MAJOR: u64 = 5;
const RPC_MAJOR: u64 = 1;
const RPC_MINOR: u64 = 2;
const FEATURE_MULTIPLEX: u64 = 1 << 0;
const FEATURE_STRUCTURED_ERRORS: u64 = 1 << 1;
const FEATURE_CBOR_QUERY: u64 = 1 << 2;
const FEATURE_IDEMPOTENCY: u64 = 1 << 3;
const FEATURE_DEADLINE: u64 = 1 << 4;
const FEATURE_CANCEL: u64 = 1 << 5;
pub const FEATURE_MEDIA_STREAMS: u64 = 1 << 6;
pub const FEATURE_VOICE_STREAMS: u64 = 1 << 7;
pub const FEATURE_ZSTD: u64 = 1 << 8;
const CLIENT_FEATURES: u64 = FEATURE_MULTIPLEX
    | FEATURE_STRUCTURED_ERRORS
    | FEATURE_CBOR_QUERY
    | FEATURE_IDEMPOTENCY
    | FEATURE_DEADLINE
    | FEATURE_CANCEL
    | FEATURE_MEDIA_STREAMS
    | FEATURE_VOICE_STREAMS
    | FEATURE_ZSTD;
const REQUIRED_FEATURES: u64 = FEATURE_MULTIPLEX
    | FEATURE_STRUCTURED_ERRORS
    | FEATURE_CBOR_QUERY
    | FEATURE_IDEMPOTENCY
    | FEATURE_DEADLINE
    | FEATURE_CANCEL;

pub mod feature {
    pub const MULTIPLEX: u64 = 1 << 0;
    pub const STRUCTURED_ERRORS: u64 = 1 << 1;
    pub const CBOR_QUERY: u64 = 1 << 2;
    pub const IDEMPOTENCY: u64 = 1 << 3;
    pub const DEADLINE: u64 = 1 << 4;
    pub const CANCEL: u64 = 1 << 5;
    pub const MEDIA_STREAMS: u64 = 1 << 6;
    pub const VOICE_STREAMS: u64 = 1 << 7;
    /// zstd-compressed `RESULT` and `EVENT_BATCH` frame payloads.
    pub const ZSTD: u64 = 1 << 8;
}

pub mod kind {
    pub const AUTH: u8 = 1;
    pub const COMMAND: u8 = 2;
    pub const QUERY: u8 = 3;
    pub const RESULT: u8 = 4;
    pub const EVENT_BATCH: u8 = 5;
    pub const ACK: u8 = 6;
    pub const ERROR: u8 = 7;
    pub const PING: u8 = 8;
    pub const PONG: u8 = 9;
    pub const HELLO: u8 = 11;
    pub const CANCEL: u8 = 12;
    pub const KEY_UPDATE: u8 = 13;
    pub const STREAM_OPEN: u8 = 14;
    pub const STREAM_DATA: u8 = 15;
    pub const STREAM_END: u8 = 16;
    pub const STREAM_ABORT: u8 = 17;
}

pub mod media_op {
    pub const UPLOAD: u16 = 1;
    pub const DOWNLOAD: u16 = 2;
    pub const STAT: u16 = 3;
    pub const DELETE: u16 = 4;
    pub const HEALTH: u16 = 5;
}

pub mod voice_op {
    pub const JOIN: u16 = 1;
}

const MEDIA_CHUNK_SIZE: usize = 256 * 1024;

pub mod op {
    pub const REGISTER: u16 = 1;
    pub const LOGIN: u16 = 2;
    pub const EMAIL_AUTH_START: u16 = 3;
    pub const EMAIL_AUTH_VERIFY: u16 = 4;
    pub const ME: u16 = 5;
    pub const ACCOUNT_DELETE: u16 = 6;
    pub const SET_USERNAME: u16 = 7;
    pub const SET_NAME: u16 = 8;
    pub const SET_PRIVACY: u16 = 9;
    pub const CONTACTS: u16 = 10;
    pub const CONTACT_ADD: u16 = 11;
    pub const CONTACT_DELETE: u16 = 12;
    pub const CREATE_GROUP: u16 = 13;
    pub const CREATE_CHANNEL: u16 = 14;
    pub const SET_CHAT_TITLE: u16 = 15;
    pub const SET_CHANNEL_USERNAME: u16 = 16;
    pub const SET_CHANNEL_COMMENTS: u16 = 17;
    pub const SEND_CHANNEL_COMMENT: u16 = 18;
    pub const CHANNEL_COMMENTS: u16 = 19;
    pub const ADD_CHAT_MEMBER: u16 = 20;
    pub const REMOVE_CHAT_MEMBER: u16 = 21;
    pub const SET_CLOUD_PASSWORD: u16 = 22;
    pub const RESET_CLOUD_PASSWORD: u16 = 23;
    pub const SESSIONS: u16 = 24;
    pub const REVOKE_SESSION: u16 = 25;
    pub const REVOKE_OTHER_SESSIONS: u16 = 26;
    pub const CREATE_BOT: u16 = 27;
    pub const RESET_BOT_TOKEN: u16 = 28;
    pub const SET_E2E_KEY: u16 = 29;
    pub const GET_E2E_KEY: u16 = 30;
    pub const SET_E2E_BACKUP: u16 = 31;
    pub const GET_E2E_BACKUP: u16 = 32;
    pub const RESET_E2E: u16 = 33;
    pub const WALLET: u16 = 34;
    pub const WALLET_SEND: u16 = 35;
    pub const WALLET_HISTORY: u16 = 36;
    pub const CALL: u16 = 37;
    pub const VOICE_TICKET: u16 = 38;
    pub const VOICE_PARTICIPANTS: u16 = 39;
    pub const SEND: u16 = 40;
    pub const EDIT: u16 = 41;
    pub const CALLBACK: u16 = 42;
    pub const REACT: u16 = 43;
    pub const REACT_PAID: u16 = 44;
    pub const READ: u16 = 45;
    pub const DELETE: u16 = 46;
    pub const FAVORITE: u16 = 47;
    pub const NODES_STATUS: u16 = 50;
    pub const CHATS: u16 = 51;
    pub const DELETE_CHAT: u16 = 52;
    pub const BAN_USER: u16 = 53;
    pub const UNBAN_USER: u16 = 54;
    pub const HISTORY: u16 = 55;
    pub const SYNC: u16 = 56;
    pub const BOT_ACK: u16 = 57;
    pub const NODE_REGISTER: u16 = 58;
    pub const NODE_LIST: u16 = 59;
    pub const OAUTH_DEVICE_REQUEST: u16 = 60;
    pub const OAUTH_DEVICE_DECISION: u16 = 61;
    pub const BOTFATHER_EXECUTE: u16 = 62;
    pub const DASTARS_CREDIT: u16 = 63;
    pub const FILE_TICKET: u16 = 65;
    pub const FORWARD: u16 = 69;
    pub const MEDIA_QUOTE: u16 = 70;
    pub const MESSAGE_PREPARE: u16 = 71;
    pub const MESSAGE_COMMIT: u16 = 72;
    pub const MESSAGE_CANCEL: u16 = 73;
    pub const SET_PROFILE_DESCRIPTION: u16 = 74;
    pub const NOTIFYBOT_DRAFT: u16 = 75;
    pub const NOTIFYBOT_CONFIRM: u16 = 76;
    pub const NOTIFYBOT_CANCEL: u16 = 77;
    pub const NOTIFYBOT_WORK: u16 = 78;
    pub const BOT_COMMANDS: u16 = 79;
    pub const STICKER_PACKS: u16 = 80;
    pub const STICKER_PACK: u16 = 81;
    pub const STICKER_CREATE: u16 = 82;
    pub const STICKER_PURCHASE: u16 = 83;
    pub const STICKER_SEND: u16 = 84;
    pub const STICKER_PRICE: u16 = 85;
    pub const AVATAR_PREPARE: u16 = 86;
    pub const AVATAR_COMMIT: u16 = 87;
    pub const AVATAR_DELETE: u16 = 88;
    pub const ACCOUNT_INACTIVITY_GET: u16 = 90;
    pub const ACCOUNT_INACTIVITY_SET: u16 = 91;
    pub const PIN: u16 = 92;
    pub const POLL_VOTE: u16 = 93;
    pub const CHAT_FAVORITES: u16 = 94;
    pub const CHAT_FAVORITE: u16 = 95;
    pub const CHAT_FOLDERS: u16 = 96;
    pub const CHAT_FOLDER: u16 = 97;
    pub const QR_LOGIN_START: u16 = 98;
    pub const QR_LOGIN_POLL: u16 = 99;
    pub const QR_LOGIN_APPROVE: u16 = 100;
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Unsigned(u64),
    Integer(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn map<K, I>(entries: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = (K, Value)>,
    {
        Self::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            Self::Integer(value) if *value >= 0 => Some(*value as u64),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Unsigned(value) if *value <= i64::MAX as u64 => Some(*value as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn encode_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_cbor_value(self, &mut out);
        out
    }

    pub fn decode_cbor(input: &[u8]) -> io::Result<Self> {
        let mut decoder = CborDecoder::new(input);
        let value = decoder.value(0)?;
        if decoder.pos != input.len() {
            return Err(invalid_data("trailing CBOR data"));
        }
        Ok(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Unsigned(value as u64)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Unsigned(value as u64)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub nodelay: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(40),
            write_timeout: Duration::from_secs(15),
            nodelay: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RequestOptions {
    /// Reuse this nonce only when retrying the exact same COMMAND payload.
    pub request_nonce: Option<[u8; 16]>,
    /// Absolute Unix epoch deadline in milliseconds. None uses the read timeout.
    pub deadline_ms: Option<u64>,
}

impl RequestOptions {
    pub fn with_request_nonce(mut self, request_nonce: [u8; 16]) -> Self {
        self.request_nonce = Some(request_nonce);
        self
    }

    pub fn with_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub kind: u8,
    pub flags: u8,
    pub status: u16,
    pub id: u64,
    pub request_nonce: [u8; 16],
    pub deadline_ms: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub details: Box<Value>,
    pub trace_id: Option<String>,
}

impl Response {
    fn from_frame(frame: Frame) -> Self {
        Self {
            kind: frame.kind,
            flags: frame.flags,
            status: frame.code,
            id: frame.id,
            request_nonce: frame.request_nonce,
            deadline_ms: frame.deadline_ms,
            payload: frame.payload.to_vec(),
        }
    }

    pub fn is_error(&self) -> bool {
        self.kind == kind::ERROR || self.status >= 400
    }

    pub fn cbor(&self) -> io::Result<Value> {
        if self.payload.is_empty() {
            return Ok(Value::Map(Vec::new()));
        }
        Value::decode_cbor(&self.payload)
    }

    pub fn into_cbor(self) -> io::Result<Value> {
        if self.payload.is_empty() {
            return Ok(Value::Map(Vec::new()));
        }
        Value::decode_cbor(&self.payload)
    }

    pub fn into_result(self) -> io::Result<Value> {
        let status = self.status;
        let is_error = self.is_error();
        let value = self.into_cbor()?;
        if is_error {
            return Err(api_response_error(status, &value));
        }
        Ok(value)
    }

    pub fn into_api_result(self) -> Result<Value, ApiError> {
        let status = self.status;
        let is_error = self.is_error();
        let value = self.into_cbor().map_err(|error| ApiError {
            status,
            code: "INVALID_ERROR_PAYLOAD".to_string(),
            message: error.to_string(),
            retryable: false,
            retry_after_ms: None,
            details: Box::new(Value::Map(Vec::new())),
            trace_id: None,
        })?;
        if !is_error {
            return Ok(value);
        }
        Err(api_error_from_value(status, &value))
    }

    pub fn api_error(&self) -> io::Result<Option<ApiError>> {
        if !self.is_error() {
            return Ok(None);
        }
        let value = self.cbor()?;
        Ok(Some(ApiError {
            status: value
                .get("status")
                .and_then(Value::as_u64)
                .unwrap_or(self.status as u64) as u16,
            code: value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("APPLICATION_ERROR")
                .to_string(),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("MST5 request failed")
                .to_string(),
            retryable: value
                .get("retryable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            retry_after_ms: value.get("retry_after_ms").and_then(Value::as_u64),
            details: Box::new(
                value
                    .get("details")
                    .cloned()
                    .unwrap_or(Value::Map(Vec::new())),
            ),
            trace_id: value
                .get("trace_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        }))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MST5 {} ({}): {}",
            self.code, self.status, self.message
        )
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub transport_major: u64,
    pub rpc_major: u64,
    pub rpc_minor: u64,
    pub features: u64,
    pub max_frame: u64,
    pub connection_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthInfo {
    pub principal_type: String,
    pub principal_id: Option<String>,
    pub scopes: Vec<String>,
    pub session_id: Option<String>,
    pub expires_at: Option<i64>,
    pub raw: Value,
}

impl AuthInfo {
    fn from_value(value: Value) -> io::Result<Self> {
        let principal_type = value
            .get("principal_type")
            .or_else(|| value.get("principal"))
            .or_else(|| value.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("anonymous")
            .to_string();
        let principal_id = value
            .get("principal_id")
            .or_else(|| value.get("id"))
            .and_then(value_as_string);
        let scopes = match value.get("scopes") {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            None | Some(Value::Null) => Vec::new(),
            Some(_) => return Err(invalid_data("invalid scopes in MST5 AUTH response")),
        };
        let session_id = value.get("session_id").and_then(value_as_string);
        let expires_at = value.get("expires_at").and_then(Value::as_i64);
        Ok(Self {
            principal_type,
            principal_id,
            scopes,
            session_id,
            expires_at,
            raw: value,
        })
    }
}

pub struct EventReceiver {
    pub(crate) receiver: tokio::sync::broadcast::Receiver<Response>,
}

impl EventReceiver {
    pub async fn recv(&mut self) -> io::Result<Response> {
        match self.receiver.recv().await {
            Ok(event) => Ok(event),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => Err(
                io::Error::other(format!("MST5 event receiver lagged by {skipped} batches")),
            ),
            Err(tokio::sync::broadcast::error::RecvError::Closed) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MST5 event channel closed",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub name: Option<String>,
    pub description: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub verified: bool,
    pub bot: bool,
    pub created_at: Option<i64>,
    pub kind: Option<String>,
    pub message_privacy: Option<String>,
    pub call_privacy: Option<String>,
    pub invite_privacy: Option<String>,
}

impl User {
    fn from_value(value: &Value) -> io::Result<Self> {
        Ok(Self {
            id: required_string(value, "id", "user")?,
            username: optional_string(value, "username")?,
            name: optional_string(value, "name")?,
            description: optional_string(value, "description")?.unwrap_or_default(),
            email: optional_string(value, "email")?,
            email_verified: optional_bool(value, "email_verified")?.unwrap_or(false),
            verified: optional_bool(value, "verified")?.unwrap_or(false),
            bot: optional_bool(value, "bot")?.unwrap_or(false),
            created_at: optional_i64(value, "created_at")?,
            kind: optional_string(value, "kind")?,
            message_privacy: optional_string(value, "message_privacy")?,
            call_privacy: optional_string(value, "call_privacy")?,
            invite_privacy: optional_string(value, "invite_privacy")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Me {
    pub user: User,
    pub cloud_password: bool,
}

impl Me {
    fn from_value(value: &Value) -> io::Result<Self> {
        let user = required_field(value, "user", "get_me response")?;
        Ok(Self {
            user: User::from_value(user)?,
            cloud_password: optional_bool(value, "cloud_password")?.unwrap_or(false),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthResult {
    pub token: String,
    pub user: User,
}

impl AuthResult {
    fn from_value(value: &Value, context: &str) -> io::Result<Self> {
        Ok(Self {
            token: required_string(value, "token", context)?,
            user: User::from_value(required_field(value, "user", context)?)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub id: i64,
    pub chat_id: String,
    pub from: User,
    pub to: User,
    pub text: String,
    pub date: i64,
    pub comment_post_id: Option<i64>,
    pub reply_to_message_id: Option<i64>,
    pub client_message_id: Option<String>,
    pub edited_at: Option<i64>,
    pub pinned_at: Option<i64>,
    pub read_at: Option<i64>,
    pub media: Vec<Value>,
    pub system: bool,
    pub data: Option<Value>,
    pub reactions: Vec<Value>,
}

impl Message {
    fn from_value(value: &Value) -> io::Result<Self> {
        let from = required_field(value, "from", "message")?;
        let to = required_field(value, "to", "message")?;
        Ok(Self {
            id: required_i64(value, "id", "message")?,
            chat_id: required_string(value, "chat_id", "message")?,
            from: User::from_value(from)?,
            to: User::from_value(to)?,
            text: required_string(value, "text", "message")?,
            date: required_i64(value, "date", "message")?,
            comment_post_id: optional_i64(value, "comment_post_id")?,
            reply_to_message_id: optional_i64(value, "reply_to_message_id")?,
            client_message_id: optional_string(value, "client_message_id")?,
            edited_at: optional_i64(value, "edited_at")?,
            pinned_at: optional_i64(value, "pinned_at")?,
            read_at: optional_i64(value, "read_at")?,
            media: optional_array(value, "media")?.unwrap_or_default(),
            system: optional_bool(value, "system")?.unwrap_or(false),
            data: value.get("data").cloned(),
            reactions: optional_array(value, "reactions")?.unwrap_or_default(),
        })
    }
}

#[derive(Clone)]
pub struct Client {
    connection: Arc<Mst5Connection>,
    principal: Arc<RwLock<Option<AuthInfo>>>,
    features: u64,
    server_hello: Arc<ServerHello>,
    read_timeout: Duration,
}

pub struct VoiceStream {
    client: Client,
    stream: connection::StreamHandle,
    read_timeout: Duration,
}

impl VoiceStream {
    pub async fn send(&self, pcm: &[u8]) -> io::Result<()> {
        if pcm.is_empty() || pcm.len() > 64 * 1024 {
            return Err(invalid_input("voice frame must contain 1..65536 bytes"));
        }
        self.stream.send(pcm.to_vec()).await
    }

    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let frame = self.stream.recv(self.read_timeout).await?;
        match frame.kind {
            kind::STREAM_DATA if frame.id == self.stream.id() && !frame.payload.is_empty() => {
                Ok(frame.payload.to_vec())
            }
            kind::STREAM_END | kind::STREAM_ABORT => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "voice stream closed",
            )),
            kind::ERROR => Err(api_response_error(
                frame.code,
                &Value::decode_cbor(&frame.payload)?,
            )),
            _ => Err(invalid_data("unexpected voice stream frame")),
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        let stream_result = self.stream.close().await;
        let client_result = self.client.close().await;
        stream_result.and(client_result)
    }
}

impl Client {
    /// Connect using the server pin embedded in this mst5-client build.
    pub async fn connect_compiled(endpoint: &str) -> io::Result<Self> {
        Self::connect(endpoint, compiled_server_public_key_b64()?).await
    }

    pub async fn connect(endpoint: &str, pinned_public_key_b64: &str) -> io::Result<Self> {
        Self::connect_with_options(endpoint, pinned_public_key_b64, ClientOptions::default()).await
    }

    pub async fn connect_with_options(
        endpoint: &str,
        pinned_public_key_b64: &str,
        options: ClientOptions,
    ) -> io::Result<Self> {
        let decoded = decode_base64(pinned_public_key_b64.trim())?;
        if decoded.len() != 32 {
            return Err(invalid_input(
                "MST5 server public key must decode to 32 bytes",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Self::connect_with_key_and_options(endpoint, key, options).await
    }

    pub async fn connect_with_key(endpoint: &str, pinned_public_key: [u8; 32]) -> io::Result<Self> {
        Self::connect_with_key_and_options(endpoint, pinned_public_key, ClientOptions::default())
            .await
    }

    pub async fn connect_with_public_keys(
        endpoint: &str,
        pinned_public_keys_b64: &[&str],
        options: ClientOptions,
    ) -> io::Result<Self> {
        if pinned_public_keys_b64.is_empty() {
            return Err(invalid_input(
                "at least one MST5 pinned public key is required",
            ));
        }
        let mut last_error = None;
        for encoded in pinned_public_keys_b64 {
            match Self::connect_with_options(endpoint, encoded, options.clone()).await {
                Ok(client) => return Ok(client),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| invalid_data("MST5 key rotation failed")))
    }

    pub async fn connect_with_keys(
        endpoint: &str,
        pinned_public_keys: &[[u8; 32]],
        options: ClientOptions,
    ) -> io::Result<Self> {
        if pinned_public_keys.is_empty() {
            return Err(invalid_input(
                "at least one MST5 pinned public key is required",
            ));
        }
        let mut last_error = None;
        for key in pinned_public_keys {
            match Self::connect_with_key_and_options(endpoint, *key, options.clone()).await {
                Ok(client) => return Ok(client),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| invalid_data("MST5 key rotation failed")))
    }

    pub async fn connect_with_key_and_options(
        endpoint: &str,
        pinned_public_key: [u8; 32],
        options: ClientOptions,
    ) -> io::Result<Self> {
        // A configured endpoint list always tries raw MST5 first, then the
        // independently-hosted M5oH fallback. This is deliberately handled
        // below the public API so media, voice, and account connections share
        // exactly the same order and pin validation.
        if endpoint.contains('|') {
            let mut last_error = None;
            for candidate in endpoint
                .split('|')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                match Self::connect_one_with_key_and_options(
                    candidate,
                    pinned_public_key,
                    options.clone(),
                )
                .await
                {
                    Ok(client) => return Ok(client),
                    Err(error) => last_error = Some(error),
                }
            }
            return Err(last_error.unwrap_or_else(|| invalid_input("MST5 endpoint list is empty")));
        }
        Self::connect_one_with_key_and_options(endpoint, pinned_public_key, options).await
    }

    async fn connect_one_with_key_and_options(
        endpoint: &str,
        pinned_public_key: [u8; 32],
        options: ClientOptions,
    ) -> io::Result<Self> {
        let endpoint = parse_endpoint(endpoint)?;
        // Raw MST5 reaches a multiplexer and therefore needs its binary route
        // preface. M5oH is already routed by its HTTP Host/route headers; the
        // bridge is connected directly to the selected upstream and must begin
        // with the Noise handshake.
        let m5oh = endpoint.m5oh.is_some();
        let mut stream = match endpoint.m5oh.as_ref() {
            Some(endpoint) => {
                m5oh::open_loopback_bridge(endpoint.clone(), options.connect_timeout).await?
            }
            None => {
                io_timeout(
                    options.connect_timeout,
                    "MST5 connect timed out",
                    TcpStream::connect(&endpoint.address),
                )
                .await?
            }
        };
        stream.set_nodelay(options.nodelay)?;
        if !m5oh {
            if let Some(route) = endpoint.route.as_deref() {
                write_router_preface(&mut stream, route, options.write_timeout).await?;
            }
        }
        let mut session = client_handshake(
            &mut stream,
            pinned_public_key,
            options.read_timeout,
            options.write_timeout,
        )
        .await?;
        let server_hello = Self::negotiate_stream(
            &mut stream,
            &mut session,
            options.read_timeout,
            options.write_timeout,
        )
        .await?;
        let features = server_hello.features;
        Ok(Self {
            connection: Mst5Connection::start(stream, session, options.write_timeout),
            principal: Arc::new(RwLock::new(None)),
            features,
            server_hello: Arc::new(server_hello),
            read_timeout: options.read_timeout,
        })
    }

    async fn negotiate_stream(
        stream: &mut TcpStream,
        session: &mut Session,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> io::Result<ServerHello> {
        let payload = Value::map([
            ("transport_major", Value::from(TRANSPORT_MAJOR)),
            ("rpc_major", Value::from(RPC_MAJOR)),
            ("rpc_minor", Value::from(RPC_MINOR)),
            ("features", Value::from(CLIENT_FEATURES)),
            ("required_features", Value::from(REQUIRED_FEATURES)),
            ("max_frame", Value::from(MST5_MAX_PLAIN_PAYLOAD)),
        ]);
        let encoded = Frame::new(kind::HELLO, 0, 0, payload.encode_cbor())?.encode()?;
        session.write_frame(stream, &encoded, write_timeout).await?;
        let response = session
            .read_frame(stream, read_timeout)
            .await?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "MST5 closed during HELLO")
            })?;
        let response = Frame::decode(&response)?;
        if response.kind != kind::HELLO || response.code != 200 || response.id != 0 {
            return Err(invalid_data("MST5.1 HELLO negotiation failed"));
        }
        let hello = Value::decode_cbor(&response.payload)?;
        if hello.get("transport_major").and_then(Value::as_u64) != Some(TRANSPORT_MAJOR)
            || hello.get("rpc_major").and_then(Value::as_u64) != Some(RPC_MAJOR)
        {
            return Err(invalid_data("invalid MST5.1 SERVER_HELLO"));
        }
        let features = hello.get("features").and_then(Value::as_u64).unwrap_or(0);
        if features & REQUIRED_FEATURES != REQUIRED_FEATURES
            || hello.get("max_frame").and_then(Value::as_u64) != Some(MST5_MAX_PLAIN_PAYLOAD as u64)
        {
            return Err(invalid_data("MST5.1 server omitted required capabilities"));
        }
        Ok(ServerHello {
            transport_major: TRANSPORT_MAJOR,
            rpc_major: RPC_MAJOR,
            rpc_minor: hello.get("rpc_minor").and_then(Value::as_u64).unwrap_or(0),
            features,
            max_frame: hello.get("max_frame").and_then(Value::as_u64).unwrap_or(0),
            connection_id: hello
                .get("connection_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    pub fn features(&self) -> u64 {
        self.features
    }

    pub fn server_hello(&self) -> &ServerHello {
        self.server_hello.as_ref()
    }

    pub fn subscribe_events(&self) -> EventReceiver {
        self.connection.subscribe()
    }

    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    /// Returns the principal established by the latest successful AUTH exchange.
    pub fn auth_info(&self) -> Option<AuthInfo> {
        self.principal
            .read()
            .ok()
            .and_then(|principal| principal.clone())
    }

    pub async fn connect_authenticated(
        endpoint: &str,
        pinned_public_key_b64: &str,
        token: &str,
    ) -> io::Result<Self> {
        let client = Self::connect(endpoint, pinned_public_key_b64).await?;
        client.authenticate(token).await?;
        Ok(client)
    }

    /// Connect and authenticate using the server pin embedded in this build.
    pub async fn connect_authenticated_compiled(endpoint: &str, token: &str) -> io::Result<Self> {
        let client = Self::connect_compiled(endpoint).await?;
        client.authenticate(token).await?;
        Ok(client)
    }

    pub async fn connect_authenticated_with_options(
        endpoint: &str,
        pinned_public_key_b64: &str,
        token: &str,
        options: ClientOptions,
    ) -> io::Result<Self> {
        let client = Self::connect_with_options(endpoint, pinned_public_key_b64, options).await?;
        client.authenticate(token).await?;
        Ok(client)
    }

    pub async fn authenticate(&self, token: &str) -> io::Result<()> {
        self.authenticate_info(token).await.map(|_| ())
    }

    pub async fn authenticate_info(&self, token: &str) -> io::Result<AuthInfo> {
        self.authenticate_info_with_client_name(token, "").await
    }

    pub async fn authenticate_info_with_client_name(
        &self,
        token: &str,
        client_name: &str,
    ) -> io::Result<AuthInfo> {
        self.authenticate_info_with_client_metadata(token, client_name, "")
            .await
    }

    /// Authenticates and records both the client label and physical device model
    /// in the server-side session. The model is informational only.
    pub async fn authenticate_info_with_client_metadata(
        &self,
        token: &str,
        client_name: &str,
        device_model: &str,
    ) -> io::Result<AuthInfo> {
        if client_name.chars().count() > 64 {
            return Err(invalid_input(
                "client_name must contain at most 64 characters",
            ));
        }
        if device_model.chars().count() > 128 || device_model.chars().any(char::is_control) {
            return Err(invalid_input(
                "device_model must contain at most 128 printable characters",
            ));
        }
        let payload = Value::map([
            ("token", Value::Text(token.to_string())),
            ("client_name", Value::Text(client_name.trim().to_string())),
            ("device_model", Value::Text(device_model.trim().to_string())),
        ])
        .encode_cbor();
        let frame = self
            .connection
            .request(kind::AUTH, 0, [0; 16], 0, payload, self.read_timeout)
            .await?;
        let response = Response::from_frame(frame);
        let value = response.into_result()?;
        let info = AuthInfo::from_value(value)?;
        self.set_principal(info.clone())?;
        Ok(info)
    }

    /// Opens a dedicated media-node connection authenticated by a signed transfer ticket.
    pub async fn connect_media(
        endpoint: &str,
        pinned_public_key_b64: &str,
        ticket: &str,
    ) -> io::Result<Self> {
        let client = Self::connect(endpoint, pinned_public_key_b64).await?;
        if client.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(invalid_data("media node omitted MEDIA_STREAMS"));
        }
        let payload = Value::map([
            ("mechanism", Value::from("media_ticket")),
            ("ticket", Value::from(ticket)),
        ])
        .encode_cbor();
        let response = Response::from_frame(
            client
                .connection
                .request(kind::AUTH, 0, [0; 16], 0, payload, client.read_timeout)
                .await?,
        );
        let raw = response.into_result().map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("media authentication failed: {error}"),
            )
        })?;
        client.set_principal(AuthInfo {
            principal_type: "media_ticket".to_string(),
            principal_id: None,
            scopes: vec!["media.transfer".to_string()],
            session_id: None,
            expires_at: None,
            raw,
        })?;
        Ok(client)
    }

    pub async fn connect_voice(
        endpoint: &str,
        pinned_public_key_b64: &str,
        ticket: &str,
    ) -> io::Result<VoiceStream> {
        let client = Self::connect(endpoint, pinned_public_key_b64).await?;
        if client.features & FEATURE_VOICE_STREAMS == 0 {
            return Err(invalid_data("server omitted VOICE_STREAMS"));
        }
        let payload = Value::map([
            ("mechanism", Value::from("voice_ticket")),
            ("ticket", Value::from(ticket)),
        ])
        .encode_cbor();
        let response = Response::from_frame(
            client
                .connection
                .request(kind::AUTH, 0, [0; 16], 0, payload, client.read_timeout)
                .await?,
        );
        let raw = response.into_result().map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("voice authentication failed: {error}"),
            )
        })?;
        client.set_principal(AuthInfo {
            principal_type: "voice_ticket".to_string(),
            principal_id: None,
            scopes: vec!["voice.stream".to_string()],
            session_id: None,
            expires_at: None,
            raw,
        })?;
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(client.read_timeout));
        let stream = client
            .connection
            .begin_stream(voice_op::JOIN, Vec::new(), deadline_ms)
            .await?;
        let accepted = stream.recv(client.read_timeout).await?;
        if accepted.kind != kind::ACK || accepted.code != 100 || accepted.id != stream.id() {
            stream.close().await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "voice stream rejected",
            ));
        }
        let read_timeout = Duration::from_secs(120);
        Ok(VoiceStream {
            client,
            stream,
            read_timeout,
        })
    }

    /// Opens a media-node connection using the internal node credential.
    pub async fn connect_media_internal(
        endpoint: &str,
        pinned_public_key_b64: &str,
        node_secret: &str,
    ) -> io::Result<Self> {
        let client = Self::connect(endpoint, pinned_public_key_b64).await?;
        if client.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(invalid_data("media node omitted MEDIA_STREAMS"));
        }
        let payload = Value::map([
            ("mechanism", Value::from("node_secret")),
            ("secret", Value::from(node_secret)),
        ])
        .encode_cbor();
        let response = Response::from_frame(
            client
                .connection
                .request(kind::AUTH, 0, [0; 16], 0, payload, client.read_timeout)
                .await?,
        );
        let raw = response.into_result()?;
        client.set_principal(AuthInfo {
            principal_type: "node".to_string(),
            principal_id: None,
            scopes: vec!["media.internal".to_string()],
            session_id: None,
            expires_at: None,
            raw,
        })?;
        Ok(client)
    }

    /// Streams exactly `size` bytes to the media node and verifies the final result.
    pub async fn upload_media<R: AsyncRead + Unpin>(
        &self,
        file_id: &str,
        size: u64,
        source: &mut R,
    ) -> io::Result<()> {
        if !self.is_authenticated() || self.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media client is not authenticated",
            ));
        }
        let open = Value::map([
            ("file_id", Value::from(file_id)),
            ("size", Value::from(size)),
        ]);
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(self.read_timeout));
        let mut pending = self
            .connection
            .begin(
                kind::STREAM_OPEN,
                media_op::UPLOAD,
                [0; 16],
                deadline_ms,
                open.encode_cbor(),
            )
            .await?;
        let accepted = pending.recv(self.read_timeout).await?;
        if accepted.id != pending.id() || accepted.kind != kind::ACK || accepted.code != 100 {
            pending.remove().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media upload rejected",
            ));
        }
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        let mut buffer = vec![0u8; MEDIA_CHUNK_SIZE];
        loop {
            let count = match source.read(&mut buffer).await {
                Ok(count) => count,
                Err(error) => {
                    pending.abort(500).await;
                    return Err(error);
                }
            };
            if count == 0 {
                break;
            }
            sent = sent.saturating_add(count as u64);
            if sent > size {
                pending.abort(400).await;
                return Err(invalid_data("media source exceeds declared size"));
            }
            hasher.update(&buffer[..count]);
            buffer.truncate(count);
            let payload = std::mem::take(&mut buffer);
            if let Err(error) = pending.send(kind::STREAM_DATA, 0, payload).await {
                pending.abort(500).await;
                return Err(error);
            }
            buffer = vec![0u8; MEDIA_CHUNK_SIZE];
        }
        if sent != size {
            pending.abort(400).await;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "media source is shorter than declared size",
            ));
        }
        let end = Value::map([
            ("size", Value::from(sent)),
            ("sha256", Value::from(media_hex(&hasher.finalize()))),
        ]);
        pending
            .send(kind::STREAM_END, 200, end.encode_cbor())
            .await?;
        let response = Response::from_frame(pending.recv(self.read_timeout).await?);
        if response.kind != kind::RESULT || response.status != 200 {
            return response.into_result().map(|_| ());
        }
        Ok(())
    }

    /// Resumes an interrupted upload. `source` must contain bytes starting at
    /// `offset`; `sha256` is the checksum of the complete file (including the
    /// already persisted prefix). The media node validates the prefix before
    /// appending, so retrying is safe and idempotent.
    pub async fn upload_media_resumable<R: AsyncRead + Unpin>(
        &self,
        file_id: &str,
        size: u64,
        offset: u64,
        sha256: &str,
        source: &mut R,
    ) -> io::Result<()> {
        if offset > size || sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid_data("invalid resumable upload checkpoint"));
        }
        if !self.is_authenticated() || self.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media client is not authenticated",
            ));
        }
        let open = Value::map([
            ("file_id", Value::from(file_id)),
            ("size", Value::from(size)),
            ("offset", Value::from(offset)),
        ]);
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(self.read_timeout));
        let mut pending = self
            .connection
            .begin(
                kind::STREAM_OPEN,
                media_op::UPLOAD,
                [0; 16],
                deadline_ms,
                open.encode_cbor(),
            )
            .await?;
        let accepted = pending.recv(self.read_timeout).await?;
        if accepted.id != pending.id() || accepted.kind != kind::ACK || accepted.code != 100 {
            pending.remove().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media upload rejected",
            ));
        }
        let accepted_offset = Value::decode_cbor(&accepted.payload)?
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(offset);
        if accepted_offset != offset {
            pending.remove().await;
            return Err(invalid_data("media node checkpoint mismatch"));
        }
        let mut sent = offset;
        let mut buffer = vec![0u8; MEDIA_CHUNK_SIZE];
        loop {
            let count = match source.read(&mut buffer).await {
                Ok(count) => count,
                Err(error) => {
                    pending.abort(500).await;
                    return Err(error);
                }
            };
            if count == 0 {
                break;
            }
            sent = sent.saturating_add(count as u64);
            if sent > size {
                pending.abort(400).await;
                return Err(invalid_data("media source exceeds declared size"));
            }
            let payload = buffer[..count].to_vec();
            if let Err(error) = pending.send(kind::STREAM_DATA, 0, payload).await {
                pending.abort(500).await;
                return Err(error);
            }
        }
        if sent != size {
            pending.abort(400).await;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "media source is shorter than declared size",
            ));
        }
        pending
            .send(
                kind::STREAM_END,
                200,
                Value::map([("size", Value::from(size)), ("sha256", Value::from(sha256))])
                    .encode_cbor(),
            )
            .await?;
        let response = Response::from_frame(pending.recv(self.read_timeout).await?);
        if response.kind != kind::RESULT || response.status != 200 {
            return response.into_result().map(|_| ());
        }
        Ok(())
    }

    /// Encrypts `source` directly into the media upload stream. Neither the
    /// managed caller nor the filesystem ever holds a complete ciphertext.
    pub async fn upload_media_e2e<R: AsyncRead + Unpin>(
        &self,
        file_id: &str,
        plaintext_size: u64,
        source: &mut R,
        identity: &e2e::Identity,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
    ) -> io::Result<()> {
        let encrypted_size = e2e::encrypted_media_size(plaintext_size)?;
        if !self.is_authenticated() || self.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media client is not authenticated",
            ));
        }
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(self.read_timeout));
        let open = Value::map([
            ("file_id", Value::from(file_id)),
            ("size", Value::from(encrypted_size)),
        ]);
        let mut pending = self
            .connection
            .begin(
                kind::STREAM_OPEN,
                media_op::UPLOAD,
                [0; 16],
                deadline_ms,
                open.encode_cbor(),
            )
            .await?;
        let accepted = pending.recv(self.read_timeout).await?;
        if accepted.id != pending.id() || accepted.kind != kind::ACK || accepted.code != 100 {
            pending.remove().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media upload rejected",
            ));
        }
        let mut encryptor =
            identity.media_encryptor(peer_public, from_id, to_id, file_id, plaintext_size)?;
        let header = encryptor.header();
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        let mut buffer = vec![0u8; e2e::MEDIA_CHUNK_SIZE];
        let header = header.to_vec();
        hasher.update(&header);
        sent = sent
            .checked_add(header.len() as u64)
            .ok_or_else(|| invalid_data("E2E media upload size overflow"))?;
        if let Err(error) = pending.send(kind::STREAM_DATA, 0, header).await {
            pending.abort(500).await;
            return Err(error);
        }
        loop {
            let count = match source.read(&mut buffer).await {
                Ok(value) => value,
                Err(error) => {
                    pending.abort(500).await;
                    return Err(error);
                }
            };
            if count == 0 {
                break;
            }
            let encrypted = encryptor.seal_chunk(&buffer[..count])?;
            hasher.update(&encrypted);
            sent = sent
                .checked_add(encrypted.len() as u64)
                .ok_or_else(|| invalid_data("E2E media upload size overflow"))?;
            if let Err(error) = pending.send(kind::STREAM_DATA, 0, encrypted).await {
                pending.abort(500).await;
                return Err(error);
            }
        }
        if let Err(error) = encryptor.finish() {
            pending.abort(400).await;
            return Err(error);
        }
        if sent != encrypted_size {
            pending.abort(500).await;
            return Err(invalid_data("E2E media ciphertext size mismatch"));
        }
        let end = Value::map([
            ("size", Value::from(sent)),
            ("sha256", Value::from(media_hex(&hasher.finalize()))),
        ]);
        pending
            .send(kind::STREAM_END, 200, end.encode_cbor())
            .await?;
        let response = Response::from_frame(pending.recv(self.read_timeout).await?);
        if response.kind != kind::RESULT || response.status != 200 {
            return response.into_result().map(|_| ());
        }
        Ok(())
    }

    /// Streams a media object into `target`, validating the announced size and SHA-256.
    pub async fn download_media<W: AsyncWrite + Unpin>(
        &self,
        file_id: &str,
        expected_size: u64,
        target: &mut W,
    ) -> io::Result<u64> {
        if !self.is_authenticated() || self.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media client is not authenticated",
            ));
        }
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(self.read_timeout));
        let mut pending = self
            .connection
            .begin(
                kind::STREAM_OPEN,
                media_op::DOWNLOAD,
                [0; 16],
                deadline_ms,
                Value::map([("file_id", Value::from(file_id))]).encode_cbor(),
            )
            .await?;
        let accepted = pending.recv(self.read_timeout).await?;
        if accepted.id != pending.id() || accepted.kind != kind::ACK || accepted.code != 100 {
            pending.remove().await;
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "media download rejected",
            ));
        }
        let metadata = Value::decode_cbor(&accepted.payload)?;
        let announced = metadata
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_data("media node omitted size"))?;
        if announced != expected_size {
            pending.abort(409).await;
            return Err(invalid_data("media size changed"));
        }
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        loop {
            let frame = pending.recv(self.read_timeout).await?;
            if frame.id != pending.id() {
                return Err(invalid_data("media stream id mismatch"));
            }
            match frame.kind {
                kind::STREAM_DATA => {
                    if frame.payload.is_empty() || frame.payload.len() > MEDIA_CHUNK_SIZE {
                        return Err(invalid_data("invalid media chunk"));
                    }
                    if let Err(error) = target.write_all(&frame.payload).await {
                        pending.abort(500).await;
                        return Err(error);
                    }
                    hasher.update(&frame.payload);
                    received += frame.payload.len() as u64;
                    if received > announced {
                        return Err(invalid_data("media exceeds announced size"));
                    }
                }
                kind::STREAM_END => {
                    let end = Value::decode_cbor(&frame.payload)?;
                    if received != announced
                        || end.get("size").and_then(Value::as_u64) != Some(received)
                        || end.get("sha256").and_then(Value::as_str)
                            != Some(media_hex(&hasher.finalize()).as_str())
                    {
                        return Err(invalid_data("media download checksum mismatch"));
                    }
                    if let Err(error) = target.flush().await {
                        pending.abort(500).await;
                        return Err(error);
                    }
                    return Ok(received);
                }
                kind::ERROR => {
                    return Err(api_response_error(
                        frame.code,
                        &Value::decode_cbor(&frame.payload)?,
                    ))
                }
                _ => return Err(invalid_data("unexpected media download frame")),
            }
        }
    }

    /// Downloads and authenticates V2 E2E media while writing recovered bytes
    /// incrementally to `target`.
    pub async fn download_media_e2e<W: AsyncWrite + Unpin>(
        &self,
        file_id: &str,
        expected_encrypted_size: u64,
        target: &mut W,
        identity: &e2e::Identity,
        peer_public: [u8; 32],
        from_id: &str,
        to_id: &str,
    ) -> io::Result<u64> {
        if !self.is_authenticated() || self.features & FEATURE_MEDIA_STREAMS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media client is not authenticated",
            ));
        }
        let deadline_ms = unix_now_ms().saturating_add(duration_ms(self.read_timeout));
        let mut pending = self
            .connection
            .begin(
                kind::STREAM_OPEN,
                media_op::DOWNLOAD,
                [0; 16],
                deadline_ms,
                Value::map([("file_id", Value::from(file_id))]).encode_cbor(),
            )
            .await?;
        let accepted = pending.recv(self.read_timeout).await?;
        if accepted.id != pending.id() || accepted.kind != kind::ACK || accepted.code != 100 {
            pending.remove().await;
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "media download rejected",
            ));
        }
        let metadata = Value::decode_cbor(&accepted.payload)?;
        let announced = metadata
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_data("media node omitted size"))?;
        if announced != expected_encrypted_size {
            pending.abort(409).await;
            return Err(invalid_data("media size changed"));
        }
        let mut decryptor = identity.media_decryptor(peer_public, from_id, to_id, file_id)?;
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        let mut plaintext = 0u64;
        loop {
            let frame = pending.recv(self.read_timeout).await?;
            if frame.id != pending.id() {
                return Err(invalid_data("media stream id mismatch"));
            }
            match frame.kind {
                kind::STREAM_DATA => {
                    if frame.payload.is_empty() || frame.payload.len() > MEDIA_CHUNK_SIZE {
                        return Err(invalid_data("invalid media chunk"));
                    }
                    received = received
                        .checked_add(frame.payload.len() as u64)
                        .ok_or_else(|| invalid_data("media size overflow"))?;
                    if received > announced {
                        return Err(invalid_data("media exceeds announced size"));
                    }
                    hasher.update(&frame.payload);
                    for chunk in decryptor.push(&frame.payload)? {
                        target.write_all(&chunk).await?;
                        plaintext += chunk.len() as u64;
                    }
                }
                kind::STREAM_END => {
                    let end = Value::decode_cbor(&frame.payload)?;
                    if received != announced
                        || end.get("size").and_then(Value::as_u64) != Some(received)
                        || end.get("sha256").and_then(Value::as_str)
                            != Some(media_hex(&hasher.finalize()).as_str())
                    {
                        return Err(invalid_data("media download checksum mismatch"));
                    }
                    let final_size = decryptor.finish()?;
                    if final_size != plaintext {
                        return Err(invalid_data("E2E media plaintext size mismatch"));
                    }
                    target.flush().await?;
                    return Ok(plaintext);
                }
                kind::ERROR => {
                    return Err(api_response_error(
                        frame.code,
                        &Value::decode_cbor(&frame.payload)?,
                    ))
                }
                _ => return Err(invalid_data("unexpected media download frame")),
            }
        }
    }

    pub async fn media_stat(&self, file_id: &str) -> io::Result<u64> {
        let value = self
            .query_value(
                media_op::STAT,
                Value::map([("file_id", Value::from(file_id))]),
            )
            .await?
            .into_result()?;
        value
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_data("media node returned invalid stat metadata"))
    }

    pub async fn media_delete(&self, file_id: &str) -> io::Result<()> {
        self.command(
            media_op::DELETE,
            Value::map([("file_id", Value::from(file_id))]),
        )
        .await?
        .into_result()
        .map(|_| ())
    }

    pub async fn media_health(&self) -> io::Result<()> {
        self.query_value(media_op::HEALTH, Value::Map(Vec::new()))
            .await?
            .into_result()
            .map(|_| ())
    }

    pub fn is_authenticated(&self) -> bool {
        self.auth_info()
            .map(|info| {
                !matches!(
                    info.principal_type.as_str(),
                    "anonymous" | "unauthenticated"
                )
            })
            .unwrap_or(false)
    }

    pub fn is_anonymous(&self) -> bool {
        self.auth_info()
            .map(|info| info.principal_type == "anonymous")
            .unwrap_or(false)
    }

    pub async fn get_me(&self) -> io::Result<Me> {
        let value = self.query(op::ME, "").await?.into_result()?;
        Me::from_value(&value)
    }

    pub async fn send<T, S>(&self, id: T, text: S) -> io::Result<Message>
    where
        T: ToString,
        S: Into<String>,
    {
        let to = id.to_string();
        let text = text.into();
        if to.trim().is_empty() {
            return Err(invalid_input("message recipient must not be empty"));
        }
        if text.trim().is_empty() {
            return Err(invalid_input("message text must not be empty"));
        }
        let value = self
            .command(
                op::SEND,
                Value::map([("to", Value::Text(to)), ("text", Value::Text(text))]),
            )
            .await?
            .into_result()?;
        message_from_result(&value, "send response")
    }

    pub async fn query(&self, opcode: u16, query: &str) -> io::Result<Response> {
        let payload = if query.is_empty() {
            Value::Map(Vec::new())
        } else {
            Value::map([("query", Value::Text(query.to_string()))])
        };
        self.query_value(opcode, payload).await
    }

    pub async fn query_value(&self, opcode: u16, payload: Value) -> io::Result<Response> {
        self.request_cbor(kind::QUERY, opcode, &payload.encode_cbor())
            .await
    }

    pub async fn command(&self, opcode: u16, payload: Value) -> io::Result<Response> {
        self.request_cbor(kind::COMMAND, opcode, &payload.encode_cbor())
            .await
    }

    pub async fn request_cbor(
        &self,
        frame_kind: u8,
        opcode: u16,
        payload: &[u8],
    ) -> io::Result<Response> {
        self.request_cbor_with_options(frame_kind, opcode, payload, RequestOptions::default())
            .await
    }

    pub async fn request_cbor_with_options(
        &self,
        frame_kind: u8,
        opcode: u16,
        payload: &[u8],
        options: RequestOptions,
    ) -> io::Result<Response> {
        if !self.has_principal() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticate() must be called before MST5 queries or commands",
            ));
        }
        if !matches!(frame_kind, kind::QUERY | kind::COMMAND) {
            return Err(invalid_input("request kind must be QUERY or COMMAND"));
        }
        let request_nonce = if frame_kind == kind::COMMAND {
            match options.request_nonce {
                Some(value) if value == [0; 16] => {
                    return Err(invalid_input("COMMAND request nonce must be non-zero"));
                }
                Some(value) => value,
                None => {
                    let mut value = [0_u8; 16];
                    getrandom::fill(&mut value)
                        .map_err(|error| invalid_data(format!("OS CSPRNG failed: {error}")))?;
                    if value == [0; 16] {
                        value[0] = 1;
                    }
                    value
                }
            }
        } else {
            if options.request_nonce.is_some() {
                return Err(invalid_input("request nonce is only valid for COMMAND"));
            }
            [0; 16]
        };
        let deadline_ms = options.deadline_ms.unwrap_or_else(|| {
            unix_now_ms().saturating_add(self.read_timeout.as_millis().min(u64::MAX as u128) as u64)
        });
        let timeout_duration = deadline_timeout(deadline_ms, self.read_timeout)?;
        self.connection
            .request(
                frame_kind,
                opcode,
                request_nonce,
                deadline_ms,
                payload.to_vec(),
                timeout_duration,
            )
            .await
            .map(Response::from_frame)
    }

    pub async fn ping(&self) -> io::Result<()> {
        let response = self
            .connection
            .request(kind::PING, 0, [0; 16], 0, Vec::new(), self.read_timeout)
            .await?;
        if response.kind == kind::PONG {
            Ok(())
        } else {
            Err(invalid_data("unexpected MST5 response to PING"))
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        self.connection.close().await
    }

    fn has_principal(&self) -> bool {
        self.principal
            .read()
            .map(|principal| principal.is_some())
            .unwrap_or(false)
    }

    fn set_principal(&self, info: AuthInfo) -> io::Result<()> {
        let mut principal = self
            .principal
            .write()
            .map_err(|_| invalid_data("MST5 authentication state lock poisoned"))?;
        *principal = Some(info);
        Ok(())
    }

    fn promote_auth_result(&self, result: &AuthResult) -> io::Result<()> {
        let session_id = self.auth_info().and_then(|info| info.session_id);
        let (principal_type, scopes) = if result.user.bot {
            ("bot", vec!["messages.send", "updates.read", "updates.ack"])
        } else {
            ("user", vec!["messenger.rpc", "oauth.decide"])
        };
        self.set_principal(AuthInfo {
            principal_type: principal_type.to_string(),
            principal_id: Some(result.user.id.clone()),
            scopes: scopes.into_iter().map(str::to_string).collect(),
            session_id,
            expires_at: None,
            raw: Value::Map(Vec::new()),
        })
    }
}

impl Client {
    pub async fn register(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
    ) -> io::Result<AuthResult> {
        self.ensure_transport_authenticated().await?;
        let mut entries = vec![
            ("username".to_string(), Value::from(username)),
            ("password".to_string(), Value::from(password)),
        ];
        if let Some(email) = email {
            entries.push(("email".to_string(), Value::from(email)));
        }
        let value = self
            .command(op::REGISTER, Value::Map(entries))
            .await?
            .into_result()?;
        let result = AuthResult::from_value(&value, "register response")?;
        self.promote_auth_result(&result)?;
        Ok(result)
    }

    pub async fn login(&self, username: &str, password: &str) -> io::Result<AuthResult> {
        self.ensure_transport_authenticated().await?;
        let value = self
            .command(
                op::LOGIN,
                Value::map([
                    ("username", Value::from(username)),
                    ("password", Value::from(password)),
                ]),
            )
            .await?
            .into_result()?;
        let result = AuthResult::from_value(&value, "login response")?;
        self.promote_auth_result(&result)?;
        Ok(result)
    }

    pub async fn login_email(&self, email: &str, password: &str) -> io::Result<AuthResult> {
        self.ensure_transport_authenticated().await?;
        let value = self
            .command(
                op::LOGIN,
                Value::map([
                    ("email", Value::from(email)),
                    ("password", Value::from(password)),
                ]),
            )
            .await?
            .into_result()?;
        let result = AuthResult::from_value(&value, "login response")?;
        self.promote_auth_result(&result)?;
        Ok(result)
    }

    pub async fn start_email_auth(&self, email: &str) -> io::Result<Value> {
        self.ensure_transport_authenticated().await?;
        self.command_result(
            op::EMAIL_AUTH_START,
            Value::map([("email", Value::from(email))]),
        )
        .await
    }

    pub async fn verify_email_auth(
        &self,
        email: &str,
        code: &str,
        cloud_password: Option<&str>,
    ) -> io::Result<AuthResult> {
        self.ensure_transport_authenticated().await?;
        let mut entries = vec![
            ("email".to_string(), Value::from(email)),
            ("code".to_string(), Value::from(code)),
        ];
        if let Some(cloud_password) = cloud_password {
            entries.push(("cloud_password".to_string(), Value::from(cloud_password)));
        }
        let value = self
            .command(op::EMAIL_AUTH_VERIFY, Value::Map(entries))
            .await?
            .into_result()?;
        let result = AuthResult::from_value(&value, "email auth response")?;
        self.promote_auth_result(&result)?;
        Ok(result)
    }

    pub async fn delete_account(&self, code: &str) -> io::Result<Value> {
        self.command_result(
            op::ACCOUNT_DELETE,
            Value::map([("code", Value::from(code))]),
        )
        .await
    }

    pub async fn set_username(&self, username: &str) -> io::Result<User> {
        let value = self
            .command_result(
                op::SET_USERNAME,
                Value::map([("username", Value::from(username))]),
            )
            .await?;
        User::from_value(required_field(&value, "user", "set_username response")?)
    }

    pub async fn set_name(&self, name: &str) -> io::Result<User> {
        let value = self
            .command_result(op::SET_NAME, Value::map([("name", Value::from(name))]))
            .await?;
        User::from_value(required_field(&value, "user", "set_name response")?)
    }

    pub async fn set_description(&self, description: &str) -> io::Result<Value> {
        self.set_profile_description(None, description).await
    }

    pub async fn set_profile_description(
        &self,
        profile: Option<&str>,
        description: &str,
    ) -> io::Result<Value> {
        let mut entries = vec![("description".to_string(), Value::from(description))];
        if let Some(profile) = profile {
            entries.push(("profile".to_string(), Value::from(profile)));
        }
        self.command_result(op::SET_PROFILE_DESCRIPTION, Value::Map(entries))
            .await
    }

    pub async fn set_privacy(
        &self,
        message_privacy: &str,
        call_privacy: &str,
        invite_privacy: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::SET_PRIVACY,
            Value::map([
                ("message_privacy", Value::from(message_privacy)),
                ("call_privacy", Value::from(call_privacy)),
                ("invite_privacy", Value::from(invite_privacy)),
            ]),
        )
        .await
    }

    pub async fn contacts(&self) -> io::Result<Value> {
        self.query_result(op::CONTACTS, "").await
    }

    pub async fn add_contact<T: ToString>(&self, user: T) -> io::Result<Value> {
        self.command_result(
            op::CONTACT_ADD,
            Value::map([("user", Value::Text(user.to_string()))]),
        )
        .await
    }

    pub async fn delete_contact<T: ToString>(&self, user: T) -> io::Result<Value> {
        self.command_result(
            op::CONTACT_DELETE,
            Value::map([("user", Value::Text(user.to_string()))]),
        )
        .await
    }

    pub async fn create_group<I, T>(&self, title: &str, members: I) -> io::Result<Value>
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        self.command_result(
            op::CREATE_GROUP,
            Value::map([
                ("title", Value::from(title)),
                ("members", string_array(members)),
            ]),
        )
        .await
    }

    pub async fn create_channel<I, T>(
        &self,
        title: &str,
        username: Option<&str>,
        members: I,
    ) -> io::Result<Value>
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        let mut entries = vec![
            ("title".to_string(), Value::from(title)),
            ("members".to_string(), string_array(members)),
        ];
        if let Some(username) = username {
            entries.push(("username".to_string(), Value::from(username)));
        }
        self.command_result(op::CREATE_CHANNEL, Value::Map(entries))
            .await
    }

    pub async fn set_chat_title<T: ToString>(&self, chat: T, title: &str) -> io::Result<Value> {
        self.command_result(
            op::SET_CHAT_TITLE,
            Value::map([
                ("chat", Value::Text(chat.to_string())),
                ("title", Value::from(title)),
            ]),
        )
        .await
    }

    pub async fn set_channel_username<T: ToString>(
        &self,
        chat: T,
        username: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::SET_CHANNEL_USERNAME,
            Value::map([
                ("chat", Value::Text(chat.to_string())),
                ("username", Value::from(username)),
            ]),
        )
        .await
    }

    pub async fn set_channel_comments<T: ToString>(
        &self,
        chat: T,
        enabled: bool,
    ) -> io::Result<Value> {
        self.command_result(
            op::SET_CHANNEL_COMMENTS,
            Value::map([
                ("chat", Value::Text(chat.to_string())),
                ("enabled", Value::Bool(enabled)),
            ]),
        )
        .await
    }

    pub async fn send_channel_comment<T: ToString>(
        &self,
        chat: T,
        post_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
        client_message_id: Option<&str>,
    ) -> io::Result<Message> {
        let mut entries = vec![
            ("chat".to_string(), Value::Text(chat.to_string())),
            ("post_id".to_string(), Value::Integer(post_id)),
            ("text".to_string(), Value::from(text)),
        ];
        if let Some(reply_to_message_id) = reply_to_message_id {
            entries.push((
                "reply_to_message_id".to_string(),
                Value::Integer(reply_to_message_id),
            ));
        }
        if let Some(client_message_id) = client_message_id {
            entries.push((
                "client_message_id".to_string(),
                Value::from(client_message_id),
            ));
        }
        let value = self
            .command_result(op::SEND_CHANNEL_COMMENT, Value::Map(entries))
            .await?;
        message_from_result(&value, "send_channel_comment response")
    }

    pub async fn channel_comments<T: ToString>(
        &self,
        chat: T,
        post_id: i64,
        before: Option<i64>,
        limit: Option<usize>,
    ) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("chat", &chat.to_string());
        query.push_i64("post_id", post_id);
        if let Some(before) = before {
            query.push_i64("before", before);
        }
        if let Some(limit) = limit {
            query.push_usize("limit", limit);
        }
        self.query_result(op::CHANNEL_COMMENTS, &query.finish())
            .await
    }

    pub async fn add_chat_member<C: ToString, U: ToString>(
        &self,
        chat: C,
        user: U,
    ) -> io::Result<Value> {
        self.command_result(
            op::ADD_CHAT_MEMBER,
            Value::map([
                ("chat", Value::Text(chat.to_string())),
                ("user", Value::Text(user.to_string())),
            ]),
        )
        .await
    }

    pub async fn remove_chat_member<C: ToString, U: ToString>(
        &self,
        chat: C,
        user: U,
    ) -> io::Result<Value> {
        self.command_result(
            op::REMOVE_CHAT_MEMBER,
            Value::map([
                ("chat", Value::Text(chat.to_string())),
                ("user", Value::Text(user.to_string())),
            ]),
        )
        .await
    }

    pub async fn set_cloud_password(
        &self,
        password: &str,
        e2e_backup: Option<Value>,
    ) -> io::Result<Value> {
        let mut entries = vec![("password".to_string(), Value::from(password))];
        if let Some(e2e_backup) = e2e_backup {
            entries.push(("e2e_backup".to_string(), e2e_backup));
        }
        self.command_result(op::SET_CLOUD_PASSWORD, Value::Map(entries))
            .await
    }

    pub async fn reset_cloud_password(&self, email: Option<&str>, code: &str) -> io::Result<Value> {
        self.ensure_transport_authenticated().await?;
        let mut entries = vec![("code".to_string(), Value::from(code))];
        if let Some(email) = email {
            entries.push(("email".to_string(), Value::from(email)));
        }
        self.command_result(op::RESET_CLOUD_PASSWORD, Value::Map(entries))
            .await
    }

    pub async fn sessions(&self) -> io::Result<Value> {
        self.query_result(op::SESSIONS, "").await
    }

    pub async fn revoke_session(&self, id: &str) -> io::Result<Value> {
        self.command_result(op::REVOKE_SESSION, Value::map([("id", Value::from(id))]))
            .await
    }

    pub async fn revoke_other_sessions(&self) -> io::Result<Value> {
        self.command_result(op::REVOKE_OTHER_SESSIONS, Value::Map(Vec::new()))
            .await
    }

    pub async fn create_bot(&self, username: &str) -> io::Result<AuthResult> {
        let value = self
            .command_result(
                op::CREATE_BOT,
                Value::map([("username", Value::from(username))]),
            )
            .await?;
        AuthResult::from_value(&value, "create_bot response")
    }

    pub async fn reset_bot_token(&self, username: &str) -> io::Result<AuthResult> {
        let value = self
            .command_result(
                op::RESET_BOT_TOKEN,
                Value::map([("username", Value::from(username))]),
            )
            .await?;
        AuthResult::from_value(&value, "reset_bot_token response")
    }

    pub async fn bot_commands(&self, bot: &str) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("bot", bot);
        self.query_result(op::BOT_COMMANDS, &query.finish()).await
    }

    pub async fn sticker_packs(&self) -> io::Result<Value> {
        self.query_result(op::STICKER_PACKS, "").await
    }

    pub async fn sticker_pack(&self, id: &str) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("id", id);
        self.query_result(op::STICKER_PACK, &query.finish()).await
    }

    pub async fn create_sticker_pack(&self, body: Value) -> io::Result<Value> {
        self.command_result(op::STICKER_CREATE, body).await
    }

    pub async fn purchase_sticker_pack(&self, id: &str) -> io::Result<Value> {
        self.command_result(op::STICKER_PURCHASE, Value::map([("id", Value::from(id))]))
            .await
    }

    pub async fn send_sticker(
        &self,
        to: &str,
        pack_id: &str,
        file_id: &str,
        client_message_id: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::STICKER_SEND,
            Value::map([
                ("to", Value::from(to)),
                ("pack_id", Value::from(pack_id)),
                ("file_id", Value::from(file_id)),
                ("client_message_id", Value::from(client_message_id)),
            ]),
        )
        .await
    }

    pub async fn set_sticker_pack_price(&self, id: &str, price_dsr: i64) -> io::Result<Value> {
        self.command_result(
            op::STICKER_PRICE,
            Value::map([
                ("id", Value::from(id)),
                ("price_dsr", Value::from(price_dsr)),
            ]),
        )
        .await
    }

    pub async fn set_e2e_key(&self, public_key_b64: &str) -> io::Result<Value> {
        self.command_result(
            op::SET_E2E_KEY,
            Value::map([
                ("version", Value::from(3_i64)),
                ("public_key", Value::from(public_key_b64)),
            ]),
        )
        .await
    }

    /// Registers a public E2E key scoped to a group/channel. The server keeps
    /// this alongside the account key while preserving the legacy method
    /// above for direct-message clients.
    pub async fn set_chat_e2e_key(
        &self,
        chat_id: &str,
        public_key_b64: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::SET_E2E_KEY,
            Value::map([
                ("version", Value::from(3_i64)),
                ("public_key", Value::from(public_key_b64)),
                ("chat_id", Value::from(chat_id)),
            ]),
        )
        .await
    }

    pub async fn get_e2e_key<T: ToString>(&self, user: T) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("user", &user.to_string());
        self.query_result(op::GET_E2E_KEY, &query.finish()).await
    }

    pub async fn get_chat_e2e_key<T: ToString>(
        &self,
        user: T,
        chat_id: &str,
    ) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("user", &user.to_string());
        query.push("chat_id", chat_id);
        self.query_result(op::GET_E2E_KEY, &query.finish()).await
    }

    pub async fn set_e2e_backup(&self, backup: Value) -> io::Result<Value> {
        self.command_result(op::SET_E2E_BACKUP, backup).await
    }

    pub async fn get_e2e_backup(&self) -> io::Result<Value> {
        self.query_result(op::GET_E2E_BACKUP, "").await
    }

    pub async fn reset_e2e(&self) -> io::Result<Value> {
        self.command_result(
            op::RESET_E2E,
            Value::map([("confirm", Value::from("reset_e2e"))]),
        )
        .await
    }

    pub async fn wallet(&self) -> io::Result<Value> {
        self.query_result(op::WALLET, "").await
    }

    pub async fn wallet_send<T: ToString>(
        &self,
        to: T,
        amount: i64,
        comment: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> io::Result<Value> {
        let mut entries = vec![
            ("to".to_string(), Value::Text(to.to_string())),
            ("amount".to_string(), Value::Integer(amount)),
        ];
        if let Some(comment) = comment {
            entries.push(("comment".to_string(), Value::from(comment)));
        }
        if let Some(idempotency_key) = idempotency_key {
            entries.push(("idempotency_key".to_string(), Value::from(idempotency_key)));
        }
        self.command_result(op::WALLET_SEND, Value::Map(entries))
            .await
    }

    pub async fn wallet_history(&self, limit: Option<usize>) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        if let Some(limit) = limit {
            query.push_usize("limit", limit);
        }
        self.query_result(op::WALLET_HISTORY, &query.finish()).await
    }

    pub async fn call<T: ToString>(&self, to: T, action: &str) -> io::Result<Value> {
        self.command_result(
            op::CALL,
            Value::map([
                ("to", Value::Text(to.to_string())),
                ("action", Value::from(action)),
            ]),
        )
        .await
    }

    pub async fn create_voice_ticket<T: ToString>(&self, peer: T) -> io::Result<Value> {
        self.command_result(
            op::VOICE_TICKET,
            Value::map([("peer", Value::Text(peer.to_string()))]),
        )
        .await
    }

    pub async fn voice_participants<T: ToString>(&self, peer: T) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("peer", &peer.to_string());
        self.query_result(op::VOICE_PARTICIPANTS, &query.finish())
            .await
    }

    pub async fn send_advanced(&self, request: Value) -> io::Result<Message> {
        let value = self.command_result(op::SEND, request).await?;
        message_from_result(&value, "send response")
    }

    pub async fn edit_message(&self, id: i64, text: &str) -> io::Result<Message> {
        let value = self
            .command_result(
                op::EDIT,
                Value::map([("id", Value::Integer(id)), ("text", Value::from(text))]),
            )
            .await?;
        message_from_result(&value, "edit_message response")
    }

    pub async fn edit_message_advanced(&self, request: Value) -> io::Result<Message> {
        let value = self.command_result(op::EDIT, request).await?;
        message_from_result(&value, "edit_message response")
    }

    pub async fn pin_message(&self, id: i64, pinned: bool) -> io::Result<Message> {
        let value = self
            .command_result(
                op::PIN,
                Value::map([("id", Value::Integer(id)), ("pinned", Value::Bool(pinned))]),
            )
            .await?;
        message_from_result(&value, "pin_message response")
    }

    pub async fn vote_poll(&self, message_id: i64, option: i64) -> io::Result<Message> {
        let value = self
            .command_result(
                op::POLL_VOTE,
                Value::map([
                    ("message_id", Value::Integer(message_id)),
                    ("option", Value::Integer(option)),
                ]),
            )
            .await?;
        message_from_result(&value, "vote_poll response")
    }

    pub async fn callback<T: ToString>(
        &self,
        to: T,
        message_id: i64,
        callback: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::CALLBACK,
            Value::map([
                ("to", Value::Text(to.to_string())),
                ("message_id", Value::Integer(message_id)),
                ("callback", Value::from(callback)),
            ]),
        )
        .await
    }

    pub async fn react(&self, message_id: i64, emoji: &str) -> io::Result<Value> {
        self.command_result(
            op::REACT,
            Value::map([
                ("message_id", Value::Integer(message_id)),
                ("emoji", Value::from(emoji)),
            ]),
        )
        .await
    }

    pub async fn react_paid(
        &self,
        message_id: i64,
        amount: i64,
        idempotency_key: Option<&str>,
    ) -> io::Result<Value> {
        let mut entries = vec![
            ("message_id".to_string(), Value::Integer(message_id)),
            ("amount".to_string(), Value::Integer(amount)),
        ];
        if let Some(idempotency_key) = idempotency_key {
            entries.push(("idempotency_key".to_string(), Value::from(idempotency_key)));
        }
        self.command_result(op::REACT_PAID, Value::Map(entries))
            .await
    }

    pub async fn read_messages<T: ToString>(&self, peer: T) -> io::Result<Value> {
        self.command_result(
            op::READ,
            Value::map([("peer", Value::Text(peer.to_string()))]),
        )
        .await
    }

    pub async fn delete_message(&self, id: i64) -> io::Result<Value> {
        self.command_result(op::DELETE, Value::map([("id", Value::Integer(id))]))
            .await
    }

    pub async fn favorite_message(&self, id: i64) -> io::Result<Message> {
        let value = self
            .command_result(op::FAVORITE, Value::map([("id", Value::Integer(id))]))
            .await?;
        message_from_result(&value, "favorite_message response")
    }

    pub async fn nodes_status(&self) -> io::Result<Value> {
        self.query_result(op::NODES_STATUS, "").await
    }

    pub async fn chats(&self) -> io::Result<Value> {
        self.query_result(op::CHATS, "").await
    }

    pub async fn delete_chat<T: ToString>(&self, peer: T) -> io::Result<Value> {
        self.command_result(
            op::DELETE_CHAT,
            Value::map([("peer", Value::Text(peer.to_string()))]),
        )
        .await
    }

    pub async fn ban_user(&self, username: &str) -> io::Result<Value> {
        self.command_result(
            op::BAN_USER,
            Value::map([("username", Value::from(username))]),
        )
        .await
    }

    pub async fn unban_user(&self, username: &str) -> io::Result<Value> {
        self.command_result(
            op::UNBAN_USER,
            Value::map([("username", Value::from(username))]),
        )
        .await
    }

    pub async fn history<T: ToString>(
        &self,
        peer: T,
        after: Option<i64>,
        before: Option<i64>,
        limit: Option<usize>,
    ) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("peer", &peer.to_string());
        if let Some(after) = after {
            query.push_i64("after", after);
        }
        if let Some(before) = before {
            query.push_i64("before", before);
        }
        if let Some(limit) = limit {
            query.push_usize("limit", limit);
        }
        self.query_result(op::HISTORY, &query.finish()).await
    }

    pub async fn updates(
        &self,
        after: Option<i64>,
        timeout_secs: Option<u64>,
    ) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        if let Some(after) = after {
            query.push_i64("after", after);
        }
        if let Some(timeout_secs) = timeout_secs {
            query.push_u64("timeout", timeout_secs);
        }
        self.query_result(op::SYNC, &query.finish()).await
    }

    pub async fn ack_updates(&self, ids: &[i64]) -> io::Result<Value> {
        self.command_result(
            op::BOT_ACK,
            Value::map([(
                "ids",
                Value::Array(ids.iter().copied().map(Value::Integer).collect()),
            )]),
        )
        .await
    }

    pub async fn register_node(&self, request: Value) -> io::Result<Value> {
        self.command_result(op::NODE_REGISTER, request).await
    }

    pub async fn list_nodes(&self) -> io::Result<Value> {
        self.query_result(op::NODE_LIST, "").await
    }

    pub async fn oauth_device_request(&self, user_code: &str) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("user_code", user_code);
        self.query_result(op::OAUTH_DEVICE_REQUEST, &query.finish())
            .await
    }

    pub async fn oauth_device_decision(
        &self,
        user_code: &str,
        decision: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::OAUTH_DEVICE_DECISION,
            Value::map([
                ("user_code", Value::from(user_code)),
                ("decision", Value::from(decision)),
            ]),
        )
        .await
    }

    pub async fn botfather_execute(
        &self,
        event_id: i64,
        user_id: i64,
        text: &str,
    ) -> io::Result<Value> {
        self.command_result(
            op::BOTFATHER_EXECUTE,
            Value::map([
                ("event_id", Value::Integer(event_id)),
                ("user_id", Value::Integer(user_id)),
                ("text", Value::from(text)),
            ]),
        )
        .await
    }

    pub async fn dastars_credit(&self, user_id: i64, amount: i64, txid: &str) -> io::Result<Value> {
        self.command_result(
            op::DASTARS_CREDIT,
            Value::map([
                ("user_id", Value::Integer(user_id)),
                ("amount", Value::Integer(amount)),
                ("txid", Value::from(txid)),
            ]),
        )
        .await
    }

    pub async fn file_ticket(&self, id: &str) -> io::Result<Value> {
        let mut query = QueryBuilder::new();
        query.push("id", id);
        self.query_result(op::FILE_TICKET, &query.finish()).await
    }

    pub async fn forward_message<T: ToString>(
        &self,
        message_id: i64,
        to: T,
        client_message_id: Option<&str>,
    ) -> io::Result<Message> {
        let mut entries = vec![
            ("message_id".to_string(), Value::Integer(message_id)),
            ("to".to_string(), Value::Text(to.to_string())),
        ];
        if let Some(client_message_id) = client_message_id {
            entries.push((
                "client_message_id".to_string(),
                Value::from(client_message_id),
            ));
        }
        let value = self
            .command_result(op::FORWARD, Value::Map(entries))
            .await?;
        message_from_result(&value, "forward_message response")
    }

    pub async fn media_quote(&self, request: Value) -> io::Result<Value> {
        self.command_result(op::MEDIA_QUOTE, request).await
    }

    pub async fn prepare_message_media(&self, request: Value) -> io::Result<Value> {
        self.command_result(op::MESSAGE_PREPARE, request).await
    }

    pub async fn commit_message_media(&self, operation_id: &str) -> io::Result<Value> {
        self.command_result(
            op::MESSAGE_COMMIT,
            Value::map([("operation_id", Value::from(operation_id))]),
        )
        .await
    }

    pub async fn cancel_message_media(
        &self,
        operation_id: Option<&str>,
        client_message_id: Option<&str>,
    ) -> io::Result<Value> {
        let mut entries = Vec::new();
        if let Some(operation_id) = operation_id {
            entries.push(("operation_id".to_string(), Value::from(operation_id)));
        }
        if let Some(client_message_id) = client_message_id {
            entries.push((
                "client_message_id".to_string(),
                Value::from(client_message_id),
            ));
        }
        self.command_result(op::MESSAGE_CANCEL, Value::Map(entries))
            .await
    }

    async fn ensure_transport_authenticated(&self) -> io::Result<()> {
        if !self.has_principal() {
            self.authenticate("").await?;
        }
        Ok(())
    }

    async fn query_result(&self, opcode: u16, query: &str) -> io::Result<Value> {
        self.query(opcode, query).await?.into_result()
    }

    async fn command_result(&self, opcode: u16, payload: Value) -> io::Result<Value> {
        self.command(opcode, payload).await?.into_result()
    }
}

struct QueryBuilder {
    value: String,
}

impl QueryBuilder {
    fn new() -> Self {
        Self {
            value: String::new(),
        }
    }

    fn push(&mut self, key: &str, value: &str) {
        if !self.value.is_empty() {
            self.value.push('&');
        }
        self.value.push_str(&percent_encode(key));
        self.value.push('=');
        self.value.push_str(&percent_encode(value));
    }

    fn push_i64(&mut self, key: &str, value: i64) {
        self.push(key, &value.to_string());
    }

    fn push_u64(&mut self, key: &str, value: u64) {
        self.push(key, &value.to_string());
    }

    fn push_usize(&mut self, key: &str, value: usize) {
        self.push(key, &value.to_string());
    }

    fn finish(self) -> String {
        self.value
    }
}

fn string_array<I, T>(values: I) -> Value
where
    I: IntoIterator<Item = T>,
    T: ToString,
{
    Value::Array(
        values
            .into_iter()
            .map(|value| Value::Text(value.to_string()))
            .collect(),
    )
}

fn message_from_result(value: &Value, context: &str) -> io::Result<Message> {
    Message::from_value(required_field(value, "message", context)?)
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[derive(Clone, Debug)]
struct Frame {
    kind: u8,
    flags: u8,
    code: u16,
    id: u64,
    request_nonce: [u8; 16],
    deadline_ms: u64,
    payload: Bytes,
}

impl Frame {
    fn new(kind: u8, code: u16, id: u64, payload: impl Into<Bytes>) -> io::Result<Self> {
        let payload = payload.into();
        if !valid_kind(kind) {
            return Err(invalid_input("invalid MST5 frame kind"));
        }
        if payload.len() > MST5_MAX_PLAIN_PAYLOAD {
            return Err(invalid_input("MST5 payload is too large"));
        }
        Ok(Self {
            kind,
            flags: 0,
            code,
            id,
            request_nonce: [0; 16],
            deadline_ms: 0,
            payload,
        })
    }

    fn request(
        kind: u8,
        code: u16,
        id: u64,
        request_nonce: [u8; 16],
        deadline_ms: u64,
        payload: impl Into<Bytes>,
    ) -> io::Result<Self> {
        let mut frame = Self::new(kind, code, id, payload)?;
        frame.request_nonce = request_nonce;
        frame.deadline_ms = deadline_ms;
        Ok(frame)
    }

    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(MST5_HEADER_LEN + self.payload.len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.flags != 0 {
            return Err(invalid_input("client MST5 frames must not use compression"));
        }
        if self.payload.len() > MST5_MAX_WIRE_PAYLOAD {
            return Err(invalid_input("MST5 wire payload is too large"));
        }
        out.clear();
        out.reserve(MST5_HEADER_LEN + self.payload.len());
        out.push(self.kind);
        out.push(self.flags);
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.request_nonce);
        out.extend_from_slice(&self.deadline_ms.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    fn decode(input: &[u8]) -> io::Result<Self> {
        let mut zstd = zstd::bulk::Decompressor::new()
            .map_err(|_| invalid_data("cannot initialize MST5 zstd decompressor"))?;
        Self::decode_with_zstd(input, &mut zstd)
    }

    fn decode_with_zstd(input: &[u8], zstd: &mut zstd::bulk::Decompressor<'_>) -> io::Result<Self> {
        if input.len() < MST5_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short MST5 frame",
            ));
        }
        let kind = input[0];
        let flags = input[1];
        if !valid_kind(kind)
            || flags & !(MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD) != 0
            || flags & (MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD) == (MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD)
        {
            return Err(invalid_data("invalid MST5 frame header"));
        }
        if flags & (MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD) != 0
            && !matches!(kind, kind::RESULT | kind::EVENT_BATCH)
        {
            return Err(invalid_data("compressed MST5 control frame"));
        }
        let code = u16::from_be_bytes([input[2], input[3]]);
        let id = u64::from_be_bytes(
            input[4..12]
                .try_into()
                .map_err(|_| invalid_data("invalid MST5 id"))?,
        );
        let request_nonce = input[12..28]
            .try_into()
            .map_err(|_| invalid_data("invalid MST5 request nonce"))?;
        let deadline_ms = u64::from_be_bytes(
            input[28..36]
                .try_into()
                .map_err(|_| invalid_data("invalid MST5 deadline"))?,
        );
        let payload_len = u32::from_be_bytes(
            input[36..40]
                .try_into()
                .map_err(|_| invalid_data("invalid MST5 payload length"))?,
        ) as usize;
        if payload_len > MST5_MAX_WIRE_PAYLOAD || input.len() != MST5_HEADER_LEN + payload_len {
            return Err(invalid_data("invalid MST5 payload length"));
        }
        let wire_payload = &input[MST5_HEADER_LEN..];
        let payload = if flags & MST5_FLAG_DEFLATE != 0 {
            decompress_to_vec_with_limit(wire_payload, MST5_MAX_PLAIN_PAYLOAD)
                .map_err(|_| invalid_data("invalid or oversized MST5 deflate payload"))?
        } else if flags & MST5_FLAG_ZSTD != 0 {
            zstd_decompress_bounded(zstd, wire_payload, MST5_MAX_PLAIN_PAYLOAD)?
        } else {
            wire_payload.to_vec()
        };
        if payload.len() > MST5_MAX_PLAIN_PAYLOAD {
            return Err(invalid_data("inflated MST5 payload is too large"));
        }
        if flags & (MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD) != 0
            && !wire_payload.is_empty()
            && payload.len()
                > wire_payload
                    .len()
                    .saturating_mul(MST5_MAX_COMPRESSION_RATIO)
        {
            return Err(invalid_data("MST5 compression ratio exceeds limit"));
        }
        Ok(Self {
            kind,
            flags,
            code,
            id,
            request_nonce,
            deadline_ms,
            payload: Bytes::from(payload),
        })
    }
}

fn zstd_decompress_bounded(
    zstd: &mut zstd::bulk::Decompressor<'_>,
    input: &[u8],
    limit: usize,
) -> io::Result<Vec<u8>> {
    if input.is_empty() {
        return Err(invalid_data("empty MST5 zstd payload"));
    }
    let output = zstd
        .decompress(input, limit)
        .map_err(|_| invalid_data("invalid or oversized MST5 zstd payload"))?;
    if output.len() > limit {
        return Err(invalid_data("inflated MST5 payload is too large"));
    }
    if output.len() > input.len().saturating_mul(MST5_MAX_COMPRESSION_RATIO) {
        return Err(invalid_data("MST5 compression ratio exceeds limit"));
    }
    Ok(output)
}

fn valid_kind(value: u8) -> bool {
    matches!(value, kind::AUTH..=kind::PONG | kind::HELLO..=kind::STREAM_ABORT)
}

fn media_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug)]
struct Session {
    seal: CipherState,
    open: CipherState,
    handshake_hash: [u8; 32],
}

#[derive(Debug)]
struct CipherState {
    key: [u8; 32],
    nonce: u64,
    plaintext_bytes: u64,
    generation: u64,
}

#[derive(Debug)]
enum Record {
    Application(Vec<u8>),
    Close,
}

#[derive(Debug)]
struct SymmetricState {
    chaining_key: [u8; 32],
    handshake_hash: [u8; 32],
    cipher_key: Option<[u8; 32]>,
    cipher_nonce: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.chaining_key.zeroize();
        self.handshake_hash.zeroize();
        self.cipher_key.zeroize();
    }
}

impl SymmetricState {
    fn new(server_static_public: &[u8; 32]) -> Self {
        let mut initial = [0u8; 32];
        initial.copy_from_slice(PROTOCOL_NAME);
        let mut state = Self {
            chaining_key: initial,
            handshake_hash: initial,
            cipher_key: None,
            cipher_nonce: 0,
        };
        state.mix_hash(PROLOGUE);
        state.mix_hash(server_static_public);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.handshake_hash);
        input.extend_from_slice(data);
        self.handshake_hash = sha256(&input);
    }

    fn mix_key(&mut self, input_key_material: &[u8]) {
        let (new_chaining_key, new_cipher_key) = hkdf(&self.chaining_key, input_key_material);
        let mut old_chaining_key = std::mem::replace(&mut self.chaining_key, new_chaining_key);
        old_chaining_key.zeroize();
        if let Some(mut old_cipher_key) = self.cipher_key.replace(new_cipher_key) {
            old_cipher_key.zeroize();
        }
        self.cipher_nonce = 0;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let ciphertext = match &self.cipher_key {
            Some(key) => {
                let output = aead_encrypt(key, self.cipher_nonce, &self.handshake_hash, plaintext)?;
                self.cipher_nonce = self
                    .cipher_nonce
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("MST5 handshake nonce exhausted"))?;
                output
            }
            None => plaintext.to_vec(),
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let plaintext = match &self.cipher_key {
            Some(key) => {
                let output =
                    aead_decrypt(key, self.cipher_nonce, &self.handshake_hash, ciphertext)?;
                self.cipher_nonce = self
                    .cipher_nonce
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("MST5 handshake nonce exhausted"))?;
                output
            }
            None => ciphertext.to_vec(),
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (first, second) = hkdf(&self.chaining_key, &[]);
        (CipherState::new(first), CipherState::new(second))
    }
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            nonce: 0,
            plaintext_bytes: 0,
            generation: 0,
        }
    }

    fn check_limit(&self, plaintext_len: usize) -> io::Result<()> {
        if self.nonce >= MAX_RECORDS {
            return Err(invalid_data(
                "MST5 record limit reached; reconnect required",
            ));
        }
        let total = self
            .plaintext_bytes
            .checked_add(plaintext_len as u64)
            .ok_or_else(|| invalid_data("MST5 byte count overflow"))?;
        if total > MAX_PLAINTEXT_BYTES {
            return Err(invalid_data("MST5 byte limit reached; reconnect required"));
        }
        Ok(())
    }

    fn commit(&mut self, plaintext_len: usize, handshake_hash: &[u8; 32]) -> io::Result<()> {
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(plaintext_len as u64)
            .ok_or_else(|| invalid_data("MST5 byte count overflow"))?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| invalid_data("MST5 nonce exhausted"))?;
        if self.nonce >= REKEY_RECORDS || self.plaintext_bytes >= REKEY_BYTES {
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid_data("MST5 key generation exhausted"))?;
            let mut material = Vec::with_capacity(40);
            material.extend_from_slice(handshake_hash);
            material.extend_from_slice(&self.generation.to_be_bytes());
            let mut old_key = std::mem::take(&mut self.key);
            self.key = hkdf(&old_key, &material).0;
            old_key.zeroize();
            material.zeroize();
            self.nonce = 0;
            self.plaintext_bytes = 0;
        }
        Ok(())
    }
}

impl Session {
    async fn write_frame(
        &mut self,
        writer: &mut TcpStream,
        payload: &[u8],
        write_timeout: Duration,
    ) -> io::Result<()> {
        let record = self.seal_record(0, payload)?;
        let mut wire = Vec::with_capacity(4 + record.len());
        wire.extend_from_slice(&(record.len() as u32).to_be_bytes());
        wire.extend_from_slice(&record);
        io_timeout(
            write_timeout,
            "MST5 write timed out",
            writer.write_all(&wire),
        )
        .await?;
        io_timeout(write_timeout, "MST5 flush timed out", writer.flush()).await
    }

    async fn read_frame(
        &mut self,
        reader: &mut TcpStream,
        read_timeout: Duration,
    ) -> io::Result<Option<Vec<u8>>> {
        let mut size = [0u8; 4];
        io_timeout(
            read_timeout,
            "MST5 read timed out",
            reader.read_exact(&mut size),
        )
        .await?;
        let length = u32::from_be_bytes(size) as usize;
        if length < 8 + TAG_LEN || length > max_record_len() {
            return Err(invalid_data("invalid MST5 encrypted record length"));
        }
        let mut record = vec![0u8; length];
        io_timeout(
            read_timeout,
            "MST5 read timed out",
            reader.read_exact(&mut record),
        )
        .await?;
        match self.open_record(&record)? {
            Record::Application(payload) => Ok(Some(payload)),
            Record::Close => Ok(None),
        }
    }

    fn seal_record(&mut self, content_type: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
        let plaintext = transport_plaintext(content_type, payload)?;
        self.seal.check_limit(plaintext.len())?;
        let sequence = self.seal.nonce;
        let frame_length = 8usize
            .checked_add(plaintext.len())
            .and_then(|value| value.checked_add(TAG_LEN))
            .ok_or_else(|| invalid_data("MST5 record length overflow"))?;
        let aad = record_aad(&self.handshake_hash, frame_length, sequence)?;
        let ciphertext = aead_encrypt(&self.seal.key, sequence, &aad, &plaintext)?;
        let mut record = Vec::with_capacity(frame_length);
        record.extend_from_slice(&sequence.to_be_bytes());
        record.extend_from_slice(&ciphertext);
        self.seal.commit(plaintext.len(), &self.handshake_hash)?;
        Ok(record)
    }

    fn open_record(&mut self, record: &[u8]) -> io::Result<Record> {
        if record.len() < 8 + TAG_LEN || record.len() > max_record_len() {
            return Err(invalid_data("invalid MST5 encrypted record length"));
        }
        let sequence = u64::from_be_bytes(
            record[..8]
                .try_into()
                .map_err(|_| invalid_data("invalid MST5 sequence"))?,
        );
        if sequence != self.open.nonce {
            return Err(invalid_data("MST5 encrypted record sequence mismatch"));
        }
        let plaintext_len = record.len() - 8 - TAG_LEN;
        self.open.check_limit(plaintext_len)?;
        let aad = record_aad(&self.handshake_hash, record.len(), sequence)?;
        let plaintext = aead_decrypt(&self.open.key, sequence, &aad, &record[8..])?;
        let decoded = parse_transport_plaintext(&plaintext)?;
        self.open.commit(plaintext.len(), &self.handshake_hash)?;
        Ok(decoded)
    }
}

async fn client_handshake(
    stream: &mut TcpStream,
    pinned_public: [u8; 32],
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<Session> {
    let server_static = PublicKey::from(pinned_public);
    let client_private = ReusableSecret::random();
    let client_public = PublicKey::from(&client_private);
    let client_public_bytes = client_public.to_bytes();

    let mut state = SymmetricState::new(&pinned_public);
    state.mix_hash(&client_public_bytes);
    let es = client_private.diffie_hellman(&server_static);
    require_nonzero_shared(es.as_bytes())?;
    state.mix_key(es.as_bytes());
    let tag = state.encrypt_and_hash(&[])?;
    if tag.len() != TAG_LEN {
        return Err(invalid_data("invalid MST5 client handshake tag length"));
    }

    let mut hello = Vec::with_capacity(6 + HANDSHAKE_MESSAGE_LEN);
    hello.extend_from_slice(CLIENT_MAGIC);
    hello.extend_from_slice(&(HANDSHAKE_MESSAGE_LEN as u16).to_be_bytes());
    hello.extend_from_slice(&client_public_bytes);
    hello.extend_from_slice(&tag);
    io_timeout(
        write_timeout,
        "MST5 handshake write timed out",
        stream.write_all(&hello),
    )
    .await?;
    io_timeout(
        write_timeout,
        "MST5 handshake flush timed out",
        stream.flush(),
    )
    .await?;

    let mut header = [0u8; 6];
    io_timeout(
        read_timeout,
        "MST5 handshake read timed out",
        stream.read_exact(&mut header),
    )
    .await?;
    if &header[..4] != SERVER_MAGIC
        || u16::from_be_bytes([header[4], header[5]]) as usize != HANDSHAKE_MESSAGE_LEN
    {
        return Err(invalid_data("invalid MST5 server hello"));
    }
    let mut server_message = [0u8; HANDSHAKE_MESSAGE_LEN];
    io_timeout(
        read_timeout,
        "MST5 handshake read timed out",
        stream.read_exact(&mut server_message),
    )
    .await?;
    let mut server_ephemeral_bytes = [0u8; 32];
    server_ephemeral_bytes.copy_from_slice(&server_message[..32]);
    let server_ephemeral = PublicKey::from(server_ephemeral_bytes);
    state.mix_hash(&server_ephemeral_bytes);
    let ee = client_private.diffie_hellman(&server_ephemeral);
    require_nonzero_shared(ee.as_bytes())?;
    state.mix_key(ee.as_bytes());
    if !state.decrypt_and_hash(&server_message[32..])?.is_empty() {
        return Err(invalid_data("invalid MST5 server handshake payload"));
    }
    let (client_to_server, server_to_client) = state.split();
    Ok(Session {
        seal: client_to_server,
        open: server_to_client,
        handshake_hash: state.handshake_hash,
    })
}

async fn io_timeout<T, F>(duration: Duration, message: &'static str, future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    match timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, message)),
    }
}

fn require_nonzero_shared(shared: &[u8; 32]) -> io::Result<()> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(invalid_data("invalid MST5 X25519 shared secret"));
    }
    Ok(())
}

fn transport_plaintext(content_type: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    transport_plaintext_into(&mut plaintext, content_type, payload)?;
    Ok(plaintext)
}

fn transport_plaintext_into(
    plaintext: &mut Vec<u8>,
    content_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    if content_type > 1 || (content_type == 1 && !payload.is_empty()) {
        return Err(invalid_input("invalid MST5 transport content type"));
    }
    if payload.len() > MAX_TRANSPORT_PAYLOAD {
        return Err(invalid_input("MST5 transport payload is too large"));
    }
    let base = 5usize
        .checked_add(payload.len())
        .ok_or_else(|| invalid_input("MST5 transport payload overflow"))?;
    let block = if base <= LARGE_PADDING_THRESHOLD {
        PADDING_BLOCK
    } else {
        LARGE_PADDING_BLOCK
    };
    let padded = base
        .checked_add(block - 1)
        .map(|value| value / block * block)
        .ok_or_else(|| invalid_input("MST5 transport padding overflow"))?;
    plaintext.clear();
    plaintext.resize(padded, 0);
    plaintext[0] = content_type;
    plaintext[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    plaintext[5..5 + payload.len()].copy_from_slice(payload);
    Ok(())
}

fn parse_transport_plaintext(plaintext: &[u8]) -> io::Result<Record> {
    // The padding policy has changed between released MST5 versions.  A
    // record is encrypted and authenticated before it gets here, while the
    // payload length and the all-zero tail are checked below, so requiring a
    // particular padding block on receipt buys no integrity.  Accepting a
    // legacy block size keeps upgrades wire-compatible.
    if plaintext.len() < 5 {
        return Err(invalid_data("invalid MST5 transport padding length"));
    }
    let content_type = plaintext[0];
    let payload_len = u32::from_be_bytes(
        plaintext[1..5]
            .try_into()
            .map_err(|_| invalid_data("invalid MST5 transport payload length"))?,
    ) as usize;
    if payload_len > MAX_TRANSPORT_PAYLOAD || 5 + payload_len > plaintext.len() {
        return Err(invalid_data("invalid MST5 transport payload length"));
    }
    if plaintext[5 + payload_len..].iter().any(|byte| *byte != 0) {
        return Err(invalid_data("invalid MST5 transport padding"));
    }
    match content_type {
        0 => Ok(Record::Application(plaintext[5..5 + payload_len].to_vec())),
        1 if payload_len == 0 => Ok(Record::Close),
        _ => Err(invalid_data("invalid MST5 transport content type")),
    }
}

fn max_record_len() -> usize {
    let base = 5 + MAX_TRANSPORT_PAYLOAD;
    let padded = base.div_ceil(LARGE_PADDING_BLOCK) * LARGE_PADDING_BLOCK;
    8 + padded + TAG_LEN
}

fn record_aad(
    handshake_hash: &[u8; 32],
    frame_length: usize,
    sequence: u64,
) -> io::Result<Vec<u8>> {
    let length = u32::try_from(frame_length)
        .map_err(|_| invalid_data("MST5 encrypted record is too large"))?;
    let mut aad = Vec::with_capacity(RECORD_LABEL.len() + 32 + 4 + 8);
    aad.extend_from_slice(RECORD_LABEL);
    aad.extend_from_slice(handshake_hash);
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    Ok(aad)
}

fn aead_nonce(nonce: u64) -> [u8; 12] {
    let mut value = [0u8; 12];
    value[4..].copy_from_slice(&nonce.to_le_bytes());
    value
}

fn aead_encrypt(key: &[u8; 32], nonce: u64, aad: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_input("invalid ChaCha20-Poly1305 key"))?;
    let nonce_bytes = aead_nonce(nonce);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| invalid_data("MST5 encryption failed"))
}

fn aead_encrypt_in_place(
    key: &[u8; 32],
    nonce: u64,
    aad: &[u8],
    plaintext: &mut Vec<u8>,
) -> io::Result<[u8; TAG_LEN]> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_input("invalid ChaCha20-Poly1305 key"))?;
    let nonce_bytes = aead_nonce(nonce);
    cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), aad, plaintext)
        .map(Into::into)
        .map_err(|_| invalid_data("MST5 encryption failed"))
}

fn aead_decrypt(
    key: &[u8; 32],
    nonce: u64,
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> io::Result<Vec<u8>> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(invalid_data("MST5 ciphertext is too short"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_input("invalid ChaCha20-Poly1305 key"))?;
    let nonce_bytes = aead_nonce(nonce);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| invalid_data("MST5 authentication failed"))
}

fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(chaining_key), input_key_material);
    let mut output = [0u8; 64];
    hkdf.expand(&[], &mut output)
        .expect("SHA-256 HKDF output length is valid");
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&output[..32]);
    second.copy_from_slice(&output[32..]);
    output.zeroize();
    (first, second)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn deadline_timeout(deadline_ms: u64, fallback: Duration) -> io::Result<Duration> {
    if deadline_ms == 0 {
        return Ok(fallback);
    }
    let remaining = deadline_ms.saturating_sub(unix_now_ms());
    if remaining == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "MST5 request deadline has expired",
        ));
    }
    Ok(fallback.min(Duration::from_millis(remaining)))
}

fn encode_cbor_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Unsigned(value) => encode_cbor_head(0, *value, out),
        Value::Integer(value) if *value >= 0 => encode_cbor_head(0, *value as u64, out),
        Value::Integer(value) => {
            let encoded = (-1i128 - *value as i128) as u64;
            encode_cbor_head(1, encoded, out);
        }
        Value::Float(value) => {
            out.push(0xfb);
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        Value::Bytes(value) => {
            encode_cbor_head(2, value.len() as u64, out);
            out.extend_from_slice(value);
        }
        Value::Text(value) => {
            encode_cbor_head(3, value.len() as u64, out);
            out.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            encode_cbor_head(4, values.len() as u64, out);
            for value in values {
                encode_cbor_value(value, out);
            }
        }
        Value::Map(entries) => {
            encode_cbor_head(5, entries.len() as u64, out);
            for (key, value) in entries {
                encode_cbor_head(3, key.len() as u64, out);
                out.extend_from_slice(key.as_bytes());
                encode_cbor_value(value, out);
            }
        }
    }
}

fn encode_cbor_head(major: u8, value: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => {
            out.push(prefix | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct CborDecoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> CborDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn value(&mut self, depth: usize) -> io::Result<Value> {
        if depth > 64 {
            return Err(invalid_data("CBOR nesting is too deep"));
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.argument(additional)?)),
            1 => {
                let raw = self.argument(additional)?;
                let value = -1i128 - raw as i128;
                if value < i64::MIN as i128 {
                    return Err(invalid_data("CBOR negative integer is out of range"));
                }
                Ok(Value::Integer(value as i64))
            }
            2 => {
                let len = self.length(additional)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(additional)?;
                let bytes = self.take(len)?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| invalid_data("invalid UTF-8 in CBOR text"))?;
                Ok(Value::Text(text.to_string()))
            }
            4 => {
                let len = self.length(additional)?;
                if len > MST5_MAX_PLAIN_PAYLOAD {
                    return Err(invalid_data("CBOR array is too large"));
                }
                let mut values = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => {
                let len = self.length(additional)?;
                if len > MST5_MAX_PLAIN_PAYLOAD {
                    return Err(invalid_data("CBOR map is too large"));
                }
                let mut entries = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    let key = self.value(depth + 1)?;
                    let Value::Text(key) = key else {
                        return Err(invalid_data("CBOR map key must be text"));
                    };
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            7 => match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                26 => {
                    let bits = u32::from_be_bytes(
                        self.take(4)?
                            .try_into()
                            .map_err(|_| invalid_data("invalid CBOR f32"))?,
                    );
                    Ok(Value::Float(f32::from_bits(bits) as f64))
                }
                27 => {
                    let bits = u64::from_be_bytes(
                        self.take(8)?
                            .try_into()
                            .map_err(|_| invalid_data("invalid CBOR f64"))?,
                    );
                    Ok(Value::Float(f64::from_bits(bits)))
                }
                _ => Err(invalid_data("unsupported CBOR simple value")),
            },
            _ => Err(invalid_data("unsupported CBOR major type")),
        }
    }

    fn byte(&mut self) -> io::Result<u8> {
        let value = *self
            .input
            .get(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short CBOR input"))?;
        self.pos += 1;
        Ok(value)
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| invalid_data("CBOR length overflow"))?;
        if end > self.input.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short CBOR input",
            ));
        }
        let value = &self.input[self.pos..end];
        self.pos = end;
        Ok(value)
    }

    fn length(&mut self, additional: u8) -> io::Result<usize> {
        let value = self.argument(additional)?;
        usize::try_from(value).map_err(|_| invalid_data("CBOR length is too large"))
    }

    fn argument(&mut self, additional: u8) -> io::Result<u64> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => Ok(self.byte()? as u64),
            25 => Ok(u16::from_be_bytes(
                self.take(2)?
                    .try_into()
                    .map_err(|_| invalid_data("invalid CBOR u16"))?,
            ) as u64),
            26 => Ok(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| invalid_data("invalid CBOR u32"))?,
            ) as u64),
            27 => Ok(u64::from_be_bytes(
                self.take(8)?
                    .try_into()
                    .map_err(|_| invalid_data("invalid CBOR u64"))?,
            )),
            31 => Err(invalid_data("indefinite-length CBOR is not supported")),
            _ => Err(invalid_data("invalid CBOR additional information")),
        }
    }
}

fn decode_base64(input: &str) -> io::Result<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        clean.push(byte);
    }
    if clean.is_empty() {
        return Err(invalid_input("empty base64 value"));
    }
    if clean.len() % 4 == 1 {
        return Err(invalid_input("invalid base64 length"));
    }
    while clean.len() % 4 != 0 {
        clean.push(b'=');
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks_exact(4) {
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad {
            return Err(invalid_input("invalid base64 padding"));
        }
        let c = if c_pad { 0 } else { base64_value(chunk[2])? };
        let d = if d_pad { 0 } else { base64_value(chunk[3])? };
        out.push((a << 2) | (b >> 4));
        if !c_pad {
            out.push((b << 4) | (c >> 2));
        }
        if !d_pad {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn base64_value(byte: u8) -> io::Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(invalid_input("invalid base64 character")),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedEndpoint {
    address: String,
    route: Option<String>,
    m5oh: Option<m5oh::Endpoint>,
}

fn parse_endpoint(endpoint: &str) -> io::Result<ParsedEndpoint> {
    let value = endpoint.trim().trim_end_matches('/');
    // M5oH is an ordinary HTTP(S) request at the network boundary.  Keep the
    // historical `m5oh` schemes below for saved configurations, but never
    // reinterpret an `http://` endpoint as a raw TCP socket.
    if let Some(address) = value.strip_prefix("https://") {
        let (endpoint, route) = parse_m5oh_endpoint(address, 443, true)?;
        return Ok(ParsedEndpoint {
            address: String::new(),
            route,
            m5oh: Some(endpoint),
        });
    }
    if let Some(address) = value.strip_prefix("http://") {
        let (endpoint, route) = parse_m5oh_endpoint(address, 80, false)?;
        return Ok(ParsedEndpoint {
            address: String::new(),
            route,
            m5oh: Some(endpoint),
        });
    }
    if value.starts_with("tcps://") {
        return Err(invalid_input(
            "MST5 endpoint must use tcp://host:port, mst5://host:port/route, http://host, or https://host",
        ));
    }
    if let Some(routed) = value.strip_prefix("mst5://") {
        let (address, route) = routed
            .split_once('/')
            .ok_or_else(|| invalid_input("routed MST5 endpoint is missing route ID"))?;
        validate_route_id(route)?;
        return Ok(ParsedEndpoint {
            address: endpoint_socket_address(address, 8067)?,
            route: Some(route.to_string()),
            m5oh: None,
        });
    }
    let value = value.strip_prefix("tcp://").unwrap_or(value);
    if value.is_empty() || value.contains('/') {
        return Err(invalid_input("invalid MST5 endpoint"));
    }
    Ok(ParsedEndpoint {
        address: endpoint_socket_address(value, 8080)?,
        route: None,
        m5oh: None,
    })
}

fn parse_m5oh_endpoint(
    value: &str,
    default_port: u16,
    tls: bool,
) -> io::Result<(m5oh::Endpoint, Option<String>)> {
    let (address, route) = match value.split_once('/') {
        Some((address, "")) => (address, None),
        Some((address, route)) => {
            // The HTTP transport only accepts opaque packet destinations.
            // Human-readable route IDs belonged to the removed legacy router.
            if route
                .parse::<std::net::SocketAddrV4>()
                .ok()
                .filter(|address| address.port() != 0)
                .is_none()
            {
                return Err(invalid_input(
                    "M5oH endpoint must use an IP:port packet destination",
                ));
            }
            (address, Some(route.to_string()))
        }
        None => (value, None),
    };
    if address.is_empty()
        || address.contains('/')
        || address
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
    {
        return Err(invalid_input("invalid M5oH endpoint"));
    }
    let (host, port) = if let Some(inner) = address.strip_prefix('[') {
        let (host, port) = inner
            .split_once(']')
            .ok_or_else(|| invalid_input("invalid M5oH IPv6 endpoint"))?;
        let port = match port.strip_prefix(':') {
            Some(port) if !port.is_empty() => port
                .parse::<u16>()
                .map_err(|_| invalid_input("invalid M5oH endpoint port"))?,
            None => default_port,
            _ => return Err(invalid_input("invalid M5oH IPv6 endpoint")),
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = address.rsplit_once(':') {
        if host.contains(':') {
            return Err(invalid_input("M5oH IPv6 endpoints must use brackets"));
        }
        (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| invalid_input("invalid M5oH endpoint port"))?,
        )
    } else {
        (address.to_string(), default_port)
    };
    if host.is_empty() || port == 0 {
        return Err(invalid_input("invalid M5oH endpoint"));
    }
    Ok((
        m5oh::Endpoint {
            host,
            port,
            tls,
            route: route.clone(),
            packet_destination: route
                .as_deref()
                .and_then(|route| route.parse::<std::net::SocketAddrV4>().ok())
                .filter(|address| address.port() != 0),
        },
        route,
    ))
}

fn endpoint_socket_address(value: &str, default_port: u16) -> io::Result<String> {
    if value.is_empty() || value.contains('/') {
        return Err(invalid_input("invalid MST5 endpoint address"));
    }
    if value.starts_with('[') {
        return Ok(if value.contains("]:") {
            value.to_string()
        } else {
            format!("{value}:{default_port}")
        });
    }
    Ok(if value.rsplit_once(':').is_some() {
        value.to_string()
    } else {
        format!("{value}:{default_port}")
    })
}

fn validate_route_id(route: &str) -> io::Result<()> {
    let valid = !route.is_empty()
        && route.len() <= 63
        && route.as_bytes()[0].is_ascii_lowercase()
        && route.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if !valid {
        return Err(invalid_input("invalid MST5 route ID"));
    }
    Ok(())
}

async fn write_router_preface(
    stream: &mut TcpStream,
    route: &str,
    write_timeout: Duration,
) -> io::Result<()> {
    validate_route_id(route)?;
    let mut preface = Vec::with_capacity(6 + route.len());
    preface.extend_from_slice(ROUTER_MAGIC);
    preface.push(ROUTER_VERSION);
    preface.push(route.len() as u8);
    preface.extend_from_slice(route.as_bytes());
    io_timeout(
        write_timeout,
        "MST5 router preface timed out",
        stream.write_all(&preface),
    )
    .await
}

fn required_field<'a>(value: &'a Value, key: &str, context: &str) -> io::Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| invalid_data(format!("missing {key} in {context}")))
}

fn required_string(value: &Value, key: &str, context: &str) -> io::Result<String> {
    required_field(value, key, context)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_data(format!("invalid {key} in {context}")))
}

fn optional_string(value: &Value, key: &str) -> io::Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_data(format!("invalid {key} field"))),
    }
}

fn required_i64(value: &Value, key: &str, context: &str) -> io::Result<i64> {
    required_field(value, key, context)?
        .as_i64()
        .ok_or_else(|| invalid_data(format!("invalid {key} in {context}")))
}

fn optional_i64(value: &Value, key: &str) -> io::Result<Option<i64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid_data(format!("invalid {key} field"))),
    }
}

fn optional_bool(value: &Value, key: &str) -> io::Result<Option<bool>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_data(format!("invalid {key} field"))),
    }
}

fn optional_array(value: &Value, key: &str) -> io::Result<Option<Vec<Value>>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => Ok(Some(values.clone())),
        Some(_) => Err(invalid_data(format!("invalid {key} field"))),
    }
}

fn api_response_error(status: u16, value: &Value) -> io::Error {
    let error = api_error_from_value(status, value);
    let kind = match status {
        401 | 403 => io::ErrorKind::PermissionDenied,
        404 => io::ErrorKind::NotFound,
        408 => io::ErrorKind::TimedOut,
        409 => io::ErrorKind::AlreadyExists,
        400..=499 => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

fn api_error_from_value(status: u16, value: &Value) -> ApiError {
    ApiError {
        status: value
            .get("status")
            .and_then(Value::as_u64)
            .unwrap_or(status as u64) as u16,
        code: value
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("APPLICATION_ERROR")
            .to_string(),
        message: value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("MST5 request failed")
            .to_string(),
        retryable: value
            .get("retryable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        retry_after_ms: value.get("retry_after_ms").and_then(Value::as_u64),
        details: Box::new(
            value
                .get("details")
                .cloned()
                .unwrap_or(Value::Map(Vec::new())),
        ),
        trace_id: value
            .get("trace_id")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::Text(value) => Some(value.clone()),
        Value::Unsigned(value) => Some(value.to_string()),
        Value::Integer(value) => Some(value.to_string()),
        _ => None,
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_accepts_legacy_padding_block() {
        let mut plaintext = vec![0u8; 64];
        plaintext[0] = 0;
        plaintext[1..5].copy_from_slice(&2u32.to_be_bytes());
        plaintext[5..7].copy_from_slice(b"ok");

        assert!(matches!(
            parse_transport_plaintext(&plaintext).unwrap(),
            Record::Application(payload) if payload == b"ok"
        ));
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cbor_round_trip() {
        let value = Value::map([
            ("name", Value::from("alice")),
            ("enabled", Value::from(true)),
            ("count", Value::from(42u64)),
            ("delta", Value::from(-7i64)),
            (
                "items",
                Value::Array(vec![Value::Null, Value::from("x"), Value::from(1.5f64)]),
            ),
        ]);
        let encoded = value.encode_cbor();
        assert_eq!(Value::decode_cbor(&encoded).unwrap(), value);
    }

    #[test]
    fn base64_decodes_32_bytes() {
        let decoded = decode_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(decoded.len(), 32);
        assert!(decoded.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn compiled_server_pin_is_valid_when_present() {
        if let Some(value) = COMPILED_SERVER_PUBLIC_KEY_B64
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            assert_eq!(compiled_server_public_key_b64().unwrap(), value);
            assert_eq!(decode_base64(value).unwrap().len(), 32);
        } else {
            assert_eq!(
                compiled_server_public_key_b64().unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        }
    }

    #[test]
    fn frame_round_trip() {
        let frame = Frame::request(
            kind::RESULT,
            200,
            42,
            [0x5a; 16],
            1_780_000_000_000,
            b"payload".to_vec(),
        )
        .unwrap();
        let encoded = frame.encode().unwrap();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.kind, kind::RESULT);
        assert_eq!(decoded.code, 200);
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.request_nonce, [0x5a; 16]);
        assert_eq!(decoded.deadline_ms, 1_780_000_000_000);
        assert_eq!(&decoded.payload[..], b"payload");
    }

    #[test]
    fn frame_decodes_bounded_zstd_and_rejects_combined_flags() {
        let mut state = 0x6a09_e667_u32;
        let block: Vec<u8> = (0..512)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        let payload = block.repeat(16);
        let compressed = zstd::bulk::compress(&payload, 3).unwrap();
        let mut encoded = Vec::new();
        encoded.push(kind::EVENT_BATCH);
        encoded.push(MST5_FLAG_ZSTD);
        encoded.extend_from_slice(&200_u16.to_be_bytes());
        encoded.extend_from_slice(&7_u64.to_be_bytes());
        encoded.extend_from_slice(&[0_u8; 16]);
        encoded.extend_from_slice(&0_u64.to_be_bytes());
        encoded.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&compressed);
        assert_eq!(Frame::decode(&encoded).unwrap().payload, payload);
        encoded[1] = MST5_FLAG_DEFLATE | MST5_FLAG_ZSTD;
        assert!(Frame::decode(&encoded).is_err());
    }

    #[test]
    fn record_cipher_rekeys_at_the_shared_boundary() {
        let hash = [3_u8; 32];
        let key = [5_u8; 32];
        let mut sender = Session {
            seal: CipherState::new(key),
            open: CipherState::new([9; 32]),
            handshake_hash: hash,
        };
        let mut receiver = Session {
            seal: CipherState::new([9; 32]),
            open: CipherState::new(key),
            handshake_hash: hash,
        };
        sender.seal.nonce = REKEY_RECORDS - 1;
        receiver.open.nonce = REKEY_RECORDS - 1;
        let boundary = sender.seal_record(0, b"boundary").unwrap();
        match receiver.open_record(&boundary).unwrap() {
            Record::Application(payload) => assert_eq!(payload, b"boundary"),
            Record::Close => panic!("unexpected close record"),
        }
        assert_eq!(sender.seal.generation, 1);
        assert_eq!(receiver.open.generation, 1);
        let after = sender.seal_record(0, b"after").unwrap();
        match receiver.open_record(&after).unwrap() {
            Record::Application(payload) => assert_eq!(payload, b"after"),
            Record::Close => panic!("unexpected close record"),
        }
    }

    #[test]
    fn query_percent_encoding() {
        assert_eq!(percent_encode("@alice test"), "%40alice%20test");
        let mut query = QueryBuilder::new();
        query.push("peer", "@alice");
        query.push_i64("after", 42);
        assert_eq!(query.finish(), "peer=%40alice&after=42");
    }

    #[test]
    fn parses_direct_and_routed_endpoints() {
        assert_eq!(
            parse_endpoint("tcp://ms.ove.rs:8080").unwrap(),
            ParsedEndpoint {
                address: "ms.ove.rs:8080".to_string(),
                route: None,
                m5oh: None,
            }
        );
        assert_eq!(
            parse_endpoint("mst5://ms.ove.rs:8067/file-main").unwrap(),
            ParsedEndpoint {
                address: "ms.ove.rs:8067".to_string(),
                route: Some("file-main".to_string()),
                m5oh: None,
            }
        );
        assert!(parse_endpoint("mst5://ms.ove.rs:8067/MEDIA").is_err());
        assert!(parse_endpoint("mst5://ms.ove.rs:8067").is_err());
        assert_eq!(
            parse_endpoint("https://m5oh.ms.ove.rs").unwrap(),
            ParsedEndpoint {
                address: String::new(),
                route: None,
                m5oh: Some(m5oh::Endpoint {
                    host: "m5oh.ms.ove.rs".to_string(),
                    port: 443,
                    tls: true,
                    route: None,
                    packet_destination: None,
                }),
            }
        );
        assert_eq!(
            parse_endpoint("http://central-1-cdn.ms.sectorlambda.ru/").unwrap(),
            ParsedEndpoint {
                address: String::new(),
                route: None,
                m5oh: Some(m5oh::Endpoint {
                    host: "central-1-cdn.ms.sectorlambda.ru".to_string(),
                    port: 80,
                    tls: false,
                    route: None,
                    packet_destination: None,
                }),
            }
        );
        assert_eq!(
            parse_endpoint("http://central-1-cdn.ms.sectorlambda.ru/10.100.2.228:8080").unwrap(),
            ParsedEndpoint {
                address: String::new(),
                route: Some("10.100.2.228:8080".to_string()),
                m5oh: Some(m5oh::Endpoint {
                    host: "central-1-cdn.ms.sectorlambda.ru".to_string(),
                    port: 80,
                    tls: false,
                    route: Some("10.100.2.228:8080".to_string()),
                    packet_destination: Some("10.100.2.228:8080".parse().unwrap()),
                }),
            }
        );
        assert_eq!(
            parse_endpoint("http://central-1-cdn.ms.sectorlambda.ru/10.100.2.228:8080").unwrap(),
            ParsedEndpoint {
                address: String::new(),
                route: Some("10.100.2.228:8080".to_string()),
                m5oh: Some(m5oh::Endpoint {
                    host: "central-1-cdn.ms.sectorlambda.ru".to_string(),
                    port: 80,
                    tls: false,
                    route: Some("10.100.2.228:8080".to_string()),
                    packet_destination: Some("10.100.2.228:8080".parse().unwrap()),
                }),
            }
        );
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
