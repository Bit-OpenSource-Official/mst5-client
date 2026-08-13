use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use mst5_client::e2e::{Backup, Envelope, Identity, IdentityStore};
use mst5_client::{kind, op, Client, ClientOptions, RequestOptions, Value, VoiceStream};
use std::collections::HashMap;
use std::io;
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;

const BRIDGE_VERSION: jint = 2;

struct NativeClient {
    client: Client,
    token: Mutex<Option<String>>,
}

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static CLIENTS: OnceLock<Mutex<HashMap<i64, Arc<NativeClient>>>> = OnceLock::new();
static VOICES: OnceLock<Mutex<HashMap<i64, Arc<VoiceStream>>>> = OnceLock::new();
static NEXT_CLIENT: AtomicI32 = AtomicI32::new(1);
static NEXT_VOICE: AtomicI32 = AtomicI32::new(1);
static IDENTITIES: OnceLock<Mutex<HashMap<i64, Arc<Identity>>>> = OnceLock::new();
static NEXT_IDENTITY: AtomicI32 = AtomicI32::new(1);
static CRASH_FD: AtomicI32 = AtomicI32::new(-1);

fn runtime() -> Result<&'static Runtime, String> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("mst5-android")
                .worker_threads(2)
                .build()
                .map_err(|error| format!("cannot start MST5 runtime: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn clients() -> &'static Mutex<HashMap<i64, Arc<NativeClient>>> {
    CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn voices() -> &'static Mutex<HashMap<i64, Arc<VoiceStream>>> {
    VOICES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn identities() -> &'static Mutex<HashMap<i64, Arc<Identity>>> {
    IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn identity(handle: jlong) -> Result<Arc<Identity>, String> {
    identities()
        .lock()
        .map_err(|_| "MST5 E2E identity registry is poisoned".to_string())?
        .get(&handle)
        .cloned()
        .ok_or_else(|| "MST5 E2E identity is closed".to_string())
}

extern "C" fn native_crash_signal(signal: libc::c_int) {
    let fd = CRASH_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        const SIGNAL_OFFSET: usize = b"[OVE_ANDROID_CRASH_V1]\nSource: native-signal\nSignal: ".len();
        let mut line = *b"[OVE_ANDROID_CRASH_V1]\nSource: native-signal\nSignal: 00\n";
        line[SIGNAL_OFFSET] = b'0' + ((signal / 10).clamp(0, 9) as u8);
        line[SIGNAL_OFFSET + 1] = b'0' + ((signal % 10).clamp(0, 9) as u8);
        unsafe { libc::write(fd, line.as_ptr().cast(), line.len()); }
    }
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

fn java_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, String> {
    env.get_string(&value)
        .map(Into::into)
        .map_err(|error| format!("invalid Java string: {error}"))
}

fn java_bytes(env: &mut JNIEnv<'_>, value: JByteArray<'_>) -> Result<Vec<u8>, String> {
    env.convert_byte_array(&value)
        .map_err(|error| format!("invalid Java byte array: {error}"))
}

fn throw_io(env: &mut JNIEnv<'_>, message: impl ToString) {
    let _ = env.throw_new("java/io/IOException", message.to_string());
}

fn client(handle: jlong) -> Result<Arc<NativeClient>, String> {
    clients()
        .lock()
        .map_err(|_| "MST5 client registry is poisoned".to_string())?
        .get(&handle)
        .cloned()
        .ok_or_else(|| "MST5 native connection is closed".to_string())
}

fn voice(handle: jlong) -> Result<Arc<VoiceStream>, String> {
    voices()
        .lock()
        .map_err(|_| "MST5 voice registry is poisoned".to_string())?
        .get(&handle)
        .cloned()
        .ok_or_else(|| "MST5 voice stream is closed".to_string())
}

fn opcode(method: &str, raw_path: &str) -> Result<u16, String> {
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let value = match (method, path) {
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
        ("GET", "/file/ticket") => op::FILE_TICKET,
        ("POST", "/forward") => op::FORWARD,
        ("POST", "/media/quote") => op::MEDIA_QUOTE,
        ("POST", "/messages/prepare") => op::MESSAGE_PREPARE,
        ("POST", "/messages/commit") => op::MESSAGE_COMMIT,
        ("POST", "/messages/cancel") => op::MESSAGE_CANCEL,
        ("POST", "/profiles/description") => op::SET_PROFILE_DESCRIPTION,
        ("POST", "/internal/notifybot/draft") => op::NOTIFYBOT_DRAFT,
        ("POST", "/internal/notifybot/confirm") => op::NOTIFYBOT_CONFIRM,
        ("POST", "/internal/notifybot/cancel") => op::NOTIFYBOT_CANCEL,
        ("POST", "/internal/notifybot/work") => op::NOTIFYBOT_WORK,
        ("GET", "/nodes/status") => op::NODES_STATUS,
        ("GET", "/chats") => op::CHATS,
        ("POST", "/chats/delete") => op::DELETE_CHAT,
        ("POST", "/users/ban") => op::BAN_USER,
        ("POST", "/users/unban") => op::UNBAN_USER,
        ("GET", "/history") => op::HISTORY,
        ("GET", "/updates") => op::SYNC,
        ("GET", "/oauth/device/request") => op::OAUTH_DEVICE_REQUEST,
        ("POST", "/oauth/device/decision") => op::OAUTH_DEVICE_DECISION,
        _ => return Err(format!("unsupported MST5 operation {method} {path}")),
    };
    Ok(value)
}

fn value_from_json(value: serde_json::Value) -> Result<Value, String> {
    Ok(match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                Value::Unsigned(value)
            } else if let Some(value) = value.as_i64() {
                Value::Integer(value)
            } else if let Some(value) = value.as_f64() {
                Value::Float(value)
            } else {
                return Err("invalid JSON number".to_string());
            }
        }
        serde_json::Value::String(value) => Value::Text(value),
        serde_json::Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(value_from_json)
                .collect::<Result<_, _>>()?,
        ),
        serde_json::Value::Object(values) => Value::Map(
            values
                .into_iter()
                .map(|(key, value)| Ok((key, value_from_json(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn json_from_value(value: Value) -> Result<serde_json::Value, String> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(value) => serde_json::Value::Bool(value),
        Value::Unsigned(value) => serde_json::Value::Number(value.into()),
        Value::Integer(value) => serde_json::Value::Number(value.into()),
        Value::Float(value) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "non-finite CBOR number".to_string())?,
        Value::Bytes(value) => serde_json::Value::Array(
            value
                .into_iter()
                .map(|byte| serde_json::Value::from(byte))
                .collect(),
        ),
        Value::Text(value) => serde_json::Value::String(value),
        Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(json_from_value)
                .collect::<Result<_, _>>()?,
        ),
        Value::Map(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| Ok((key, json_from_value(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn duplicate_file(fd: jint) -> Result<std::fs::File, String> {
    let owned_fd = unsafe { libc::dup(fd) };
    if owned_fd < 0 {
        return Err(format!(
            "cannot duplicate media descriptor: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(owned_fd) })
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeVersion(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    BRIDGE_VERSION
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let endpoint = java_string(&mut env, endpoint)?;
        let public_key = java_string(&mut env, public_key)?;
        let options = ClientOptions {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(30),
            nodelay: true,
        };
        let connected = runtime()?
            .block_on(Client::connect_with_options(
                &endpoint,
                &public_key,
                options,
            ))
            .map_err(|error| error.to_string())?;
        let handle = i64::from(NEXT_CLIENT.fetch_add(1, Ordering::Relaxed));
        if handle <= 0 {
            return Err("MST5 native connection ID exhausted".to_string());
        }
        clients()
            .lock()
            .map_err(|_| "MST5 client registry is poisoned".to_string())?
            .insert(
                handle,
                Arc::new(NativeClient {
                    client: connected,
                    token: Mutex::new(None),
                }),
            );
        Ok(handle)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let removed = clients()
        .lock()
        .ok()
        .and_then(|mut values| values.remove(&handle));
    if let Some(value) = removed {
        if let Ok(runtime) = runtime() {
            if let Err(error) = runtime.block_on(value.client.close()) {
                throw_io(&mut env, error);
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeRequest(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: JString<'_>,
    method: JString<'_>,
    path: JString<'_>,
    timeout_ms: jint,
    body: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let token = java_string(&mut env, token)?;
        let method = java_string(&mut env, method)?.to_ascii_uppercase();
        let path = java_string(&mut env, path)?;
        let body = java_bytes(&mut env, body)?;
        let opcode = opcode(&method, &path)?;
        let connection = client(handle)?;
        let mut authenticated = connection
            .token
            .lock()
            .map_err(|_| "MST5 authentication state is poisoned".to_string())?;
        if authenticated.as_deref() != Some(token.as_str()) {
            runtime()?
                .block_on(connection.client.authenticate(&token))
                .map_err(|error| error.to_string())?;
            *authenticated = Some(token);
        }
        drop(authenticated);
        let frame_kind = if method == "GET" {
            kind::QUERY
        } else {
            kind::COMMAND
        };
        let payload = if frame_kind == kind::QUERY {
            let query = path.split_once('?').map(|(_, value)| value).unwrap_or("");
            if query.is_empty() {
                Value::Map(Vec::new())
            } else {
                Value::map([("query", Value::Text(query.to_string()))])
            }
        } else if body.is_empty() {
            Value::Map(Vec::new())
        } else {
            let json = serde_json::from_slice(&body)
                .map_err(|error| format!("invalid request JSON: {error}"))?;
            value_from_json(json)?
        };
        let deadline_ms = unix_now_ms().saturating_add(timeout_ms.max(1) as u64);
        let options = RequestOptions::default().with_deadline_ms(deadline_ms);
        let response = runtime()?
            .block_on(connection.client.request_cbor_with_options(
                frame_kind,
                opcode,
                &payload.encode_cbor(),
                options,
            ))
            .map_err(|error| error.to_string())?;
        let decoded = Value::decode_cbor(&response.payload).map_err(|error| error.to_string())?;
        let response_body = match decoded {
            Value::Bytes(bytes) => bytes,
            other => serde_json::to_vec(&json_from_value(other)?)
                .map_err(|error| format!("cannot encode response JSON: {error}"))?,
        };
        let mut encoded = Vec::with_capacity(3 + response_body.len());
        encoded.push(response.kind);
        encoded.extend_from_slice(&response.status.to_be_bytes());
        encoded.extend_from_slice(&response_body);
        Ok(encoded)
    })();
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw_io(&mut env, error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

struct JavaProgress {
    vm: JavaVM,
    observer: GlobalRef,
    total: u64,
}

impl JavaProgress {
    fn new(
        env: &mut JNIEnv<'_>,
        observer: JObject<'_>,
        total: u64,
    ) -> Result<Option<Self>, String> {
        if observer.is_null() {
            return Ok(None);
        }
        Ok(Some(Self {
            vm: env
                .get_java_vm()
                .map_err(|error| format!("cannot access Java VM: {error}"))?,
            observer: env
                .new_global_ref(observer)
                .map_err(|error| format!("cannot retain transfer observer: {error}"))?,
            total,
        }))
    }

    fn update(&self, completed: u64) -> io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let cancelled = env
            .call_method(self.observer.as_obj(), "isCancelled", "()Z", &[])
            .and_then(|value| value.z())
            .map_err(|error| io::Error::other(error.to_string()))?;
        if cancelled {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "media transfer cancelled",
            ));
        }
        env.call_method(
            self.observer.as_obj(),
            "onProgress",
            "(JJ)V",
            &[
                JValue::Long(completed as jlong),
                JValue::Long(self.total as jlong),
            ],
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }
}

struct ProgressReader<R> {
    inner: R,
    progress: Option<JavaProgress>,
    completed: u64,
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(progress) = &self.progress {
            if let Err(error) = progress.update(self.completed) {
                return Poll::Ready(Err(error));
            }
        }
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                self.completed += (buffer.filled().len() - before) as u64;
                if let Some(progress) = &self.progress {
                    if let Err(error) = progress.update(self.completed) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

struct ProgressWriter<W> {
    inner: W,
    progress: Option<JavaProgress>,
    completed: u64,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let Some(progress) = &self.progress {
            if let Err(error) = progress.update(self.completed) {
                return Poll::Ready(Err(error));
            }
        }
        match Pin::new(&mut self.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(count)) => {
                self.completed += count as u64;
                if let Some(progress) = &self.progress {
                    if let Err(error) = progress.update(self.completed) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct MemoryWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl AsyncWrite for MemoryWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "media download exceeds memory limit",
            )));
        }
        self.bytes.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn transfer_strings(
    env: &mut JNIEnv<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
) -> Result<(String, String, String, String), String> {
    Ok((
        java_string(env, endpoint)?,
        java_string(env, public_key)?,
        java_string(env, ticket)?,
        java_string(env, file_id)?,
    ))
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeUpload(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    size: jlong,
    fd: jint,
    observer: JObject<'_>,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        if size < 0 || fd < 0 {
            return Err("invalid media source".to_string());
        }
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let progress = JavaProgress::new(&mut env, observer, size as u64)?;
        let file = duplicate_file(fd)?;
        let mut source = ProgressReader {
            inner: tokio::fs::File::from_std(file),
            progress,
            completed: 0,
        };
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .upload_media(&file_id, size as u64, &mut source)
                    .await;
                let _ = client.close().await;
                result
            })
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(()) => JNI_TRUE,
        Err(error) => {
            throw_io(&mut env, error);
            JNI_FALSE
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDownload(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    expected_size: jlong,
    fd: jint,
    observer: JObject<'_>,
) -> jlong {
    let result = (|| -> Result<u64, String> {
        if expected_size < 0 || fd < 0 {
            return Err("invalid media target".to_string());
        }
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let progress = JavaProgress::new(&mut env, observer, expected_size as u64)?;
        let file = duplicate_file(fd)?;
        let mut target = ProgressWriter {
            inner: tokio::fs::File::from_std(file),
            progress,
            completed: 0,
        };
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .download_media(&file_id, expected_size as u64, &mut target)
                    .await;
                let _ = client.close().await;
                result
            })
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(received) => received as jlong,
        Err(error) => {
            throw_io(&mut env, error);
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDownloadBytes(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    expected_size: jlong,
    max_bytes: jint,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        if expected_size < 0 || expected_size > jint::MAX as jlong || max_bytes < 1 {
            return Err("invalid in-memory media size".to_string());
        }
        let expected_size = expected_size as usize;
        let limit = max_bytes as usize;
        if expected_size > limit {
            return Err("file is too large".to_string());
        }
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let mut target = MemoryWriter {
            bytes: Vec::with_capacity(expected_size),
            limit,
        };
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .download_media(&file_id, expected_size as u64, &mut target)
                    .await;
                let _ = client.close().await;
                result
            })
            .map_err(|error| error.to_string())?;
        Ok(target.bytes)
    })();
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw_io(&mut env, error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeVoiceOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let endpoint = java_string(&mut env, endpoint)?;
        let public_key = java_string(&mut env, public_key)?;
        let ticket = java_string(&mut env, ticket)?;
        let stream = runtime()?
            .block_on(Client::connect_voice(&endpoint, &public_key, &ticket))
            .map_err(|error| error.to_string())?;
        let handle = i64::from(NEXT_VOICE.fetch_add(1, Ordering::Relaxed));
        if handle <= 0 {
            return Err("MST5 voice stream ID exhausted".to_string());
        }
        voices()
            .lock()
            .map_err(|_| "MST5 voice registry is poisoned".to_string())?
            .insert(handle, Arc::new(stream));
        Ok(handle)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeVoiceSend(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    pcm: JByteArray<'_>,
) {
    let result = (|| -> Result<(), String> {
        let pcm = java_bytes(&mut env, pcm)?;
        runtime()?
            .block_on(voice(handle)?.send(&pcm))
            .map_err(|error| error.to_string())
    })();
    if let Err(error) = result {
        throw_io(&mut env, error);
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeVoiceReceive(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        runtime()?
            .block_on(voice(handle)?.recv())
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw_io(&mut env, error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeVoiceClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let stream = voices()
        .lock()
        .ok()
        .and_then(|mut values| values.remove(&handle));
    if let Some(stream) = stream {
        if let Ok(runtime) = runtime() {
            if let Err(error) = runtime.block_on(stream.close()) {
                throw_io(&mut env, error);
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
    create: jboolean,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let store = IdentityStore::new(java_string(&mut env, path)?);
        let value = if create != JNI_FALSE {
            store.load_or_create()
        } else {
            store
                .load()
                .and_then(|value| value.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "E2E identity not found")))
        }
        .map_err(|error| error.to_string())?;
        let handle = i64::from(NEXT_IDENTITY.fetch_add(1, Ordering::Relaxed));
        identities()
            .lock()
            .map_err(|_| "MST5 E2E identity registry is poisoned".to_string())?
            .insert(handle, Arc::new(value));
        Ok(handle)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => { throw_io(&mut env, error); 0 }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EClose(
    _env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong,
) {
    if let Ok(mut values) = identities().lock() { values.remove(&handle); }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ERemove(
    mut env: JNIEnv<'_>, _class: JClass<'_>, path: JString<'_>,
) {
    let result = java_string(&mut env, path)
        .and_then(|path| IdentityStore::new(path).remove().map_err(|error| error.to_string()));
    if let Err(error) = result { throw_io(&mut env, error); }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EPublicKey(
    mut env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong,
) -> jbyteArray {
    match identity(handle) {
        Ok(value) => env.byte_array_from_slice(&value.public_key()).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EFingerprint(
    mut env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong,
) -> jbyteArray {
    match identity(handle) {
        Ok(value) => env.byte_array_from_slice(value.fingerprint().as_bytes()).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EPublicFingerprint(
    mut env: JNIEnv<'_>, _class: JClass<'_>, public_key: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<String, String> {
        let public_key: [u8; 32] = java_bytes(&mut env, public_key)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        Ok(mst5_client::e2e::fingerprint(&public_key))
    })();
    match result {
        Ok(value) => env.byte_array_from_slice(value.as_bytes()).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ESeal(
    mut env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong, peer: JByteArray<'_>,
    from: JString<'_>, to: JString<'_>, plaintext: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let peer: [u8; 32] = java_bytes(&mut env, peer)?.try_into().map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let plaintext = java_bytes(&mut env, plaintext)?;
        let value = identity(handle)?.seal(peer, &from, &to, &plaintext).map_err(|error| error.to_string())?;
        let mut encoded = Vec::with_capacity(25 + value.ciphertext.len());
        encoded.push(value.version); encoded.extend_from_slice(&value.nonce); encoded.extend_from_slice(&value.ciphertext);
        Ok(encoded)
    })();
    match result {
        Ok(value) => env.byte_array_from_slice(&value).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EDecrypt(
    mut env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong, peer: JByteArray<'_>,
    from: JString<'_>, to: JString<'_>, encoded: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let peer: [u8; 32] = java_bytes(&mut env, peer)?.try_into().map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let encoded = java_bytes(&mut env, encoded)?;
        if encoded.len() < 41 || encoded[0] != 3 { return Err("invalid E2E v3 envelope".to_string()); }
        let value = Envelope { version: encoded[0], nonce: encoded[1..25].try_into().unwrap(), ciphertext: encoded[25..].to_vec() };
        identity(handle)?.open(peer, &from, &to, &value).map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => env.byte_array_from_slice(&value).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EBackup(
    mut env: JNIEnv<'_>, _class: JClass<'_>, handle: jlong, password: JString<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let password = java_string(&mut env, password)?;
        let value = identity(handle)?.backup(&password).map_err(|error| error.to_string())?;
        let mut encoded = Vec::with_capacity(41 + value.ciphertext.len());
        encoded.push(value.version); encoded.extend_from_slice(&value.salt); encoded.extend_from_slice(&value.nonce); encoded.extend_from_slice(&value.ciphertext);
        Ok(encoded)
    })();
    match result {
        Ok(value) => env.byte_array_from_slice(&value).map(|array| array.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(error) => { throw_io(&mut env, error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ERestore(
    mut env: JNIEnv<'_>, _class: JClass<'_>, path: JString<'_>, password: JString<'_>, encoded: JByteArray<'_>,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let path = java_string(&mut env, path)?;
        let password = java_string(&mut env, password)?;
        let encoded = java_bytes(&mut env, encoded)?;
        if encoded.len() != 89 || encoded[0] != 2 { return Err("invalid E2E backup v2".to_string()); }
        let backup = Backup { version: encoded[0], salt: encoded[1..17].try_into().unwrap(), nonce: encoded[17..41].try_into().unwrap(), ciphertext: encoded[41..].to_vec() };
        let value = Identity::restore(&backup, &password).map_err(|error| error.to_string())?;
        IdentityStore::new(path).save(&value).map_err(|error| error.to_string())?;
        let handle = i64::from(NEXT_IDENTITY.fetch_add(1, Ordering::Relaxed));
        identities().lock().map_err(|_| "MST5 E2E identity registry is poisoned".to_string())?.insert(handle, Arc::new(value));
        Ok(handle)
    })();
    match result { Ok(handle) => handle, Err(error) => { throw_io(&mut env, error); 0 } }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeInstallCrashHandler(
    mut env: JNIEnv<'_>, _class: JClass<'_>, path: JString<'_>,
) {
    let result = (|| -> Result<(), String> {
        let path = java_string(&mut env, path)?;
        let c_path = std::ffi::CString::new(path.clone()).map_err(|_| "invalid crash report path".to_string())?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o600) };
        if fd < 0 { return Err(format!("cannot open native crash report: {}", io::Error::last_os_error())); }
        let previous_fd = CRASH_FD.swap(fd, Ordering::SeqCst);
        if previous_fd >= 0 { unsafe { libc::close(previous_fd); } }
        for signal in [libc::SIGABRT, libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
            unsafe { libc::signal(signal, native_crash_signal as *const () as libc::sighandler_t); }
        }
        std::panic::set_hook(Box::new(move |info| {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = writeln!(file, "[OVE_ANDROID_CRASH_V1]\nSource: rust-panic\n{info}");
                let _ = file.sync_all();
            }
        }));
        Ok(())
    })();
    if let Err(error) = result { throw_io(&mut env, error); }
}
