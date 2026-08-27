use jni::objects::{
    GlobalRef, JByteArray, JByteBuffer, JClass, JIntArray, JLongArray, JObject, JObjectArray,
    JString, JValue,
};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use mst5_client::e2e::{
    Backup, Envelope, Identity, IdentityStore, ENVELOPE_VERSION, LEGACY_ENVELOPE_VERSION,
};
use mst5_client::messenger::{MessengerConfig, MessengerCore, SessionStorage, TransportMode};
use mst5_client::{compiled_server_public_key_b64, Client, RequestOptions, VoiceStream};
use std::collections::HashMap;
use std::io;
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;

const BRIDGE_VERSION: jint = 7;

struct NativeClient {
    messenger: MessengerCore,
}

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static CLIENTS: OnceLock<Mutex<HashMap<i64, Arc<NativeClient>>>> = OnceLock::new();
static VOICES: OnceLock<Mutex<HashMap<i64, Arc<VoiceStream>>>> = OnceLock::new();
static NEXT_CLIENT: AtomicI32 = AtomicI32::new(1);
static NEXT_VOICE: AtomicI32 = AtomicI32::new(1);
static IDENTITIES: OnceLock<Mutex<HashMap<i64, Arc<Identity>>>> = OnceLock::new();
static NEXT_IDENTITY: AtomicI32 = AtomicI32::new(1);
static CRASH_FD: AtomicI32 = AtomicI32::new(-1);
static SESSION_STORAGE: OnceLock<Mutex<Option<SessionStorage>>> = OnceLock::new();

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

fn session_storage() -> &'static Mutex<Option<SessionStorage>> {
    SESSION_STORAGE.get_or_init(|| Mutex::new(None))
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
        const SIGNAL_OFFSET: usize =
            b"[OVE_ANDROID_CRASH_V1]\nSource: native-signal\nSignal: ".len();
        let mut line = *b"[OVE_ANDROID_CRASH_V1]\nSource: native-signal\nSignal: 00\n";
        line[SIGNAL_OFFSET] = b'0' + ((signal / 10).clamp(0, 9) as u8);
        line[SIGNAL_OFFSET + 1] = b'0' + ((signal % 10).clamp(0, 9) as u8);
        unsafe {
            libc::write(fd, line.as_ptr().cast(), line.len());
        }
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

/// Opens the persistent messenger state once the Android application supplies
/// its private files directory.  Legacy Java properties are imported by the
/// platform adapter on first use; Rust owns every write thereafter.
#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeOpenSessionStore(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    root: JString<'_>,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        let root = java_string(&mut env, root)?;
        let store = SessionStorage::open(root).map_err(|error| error.to_string())?;
        *session_storage()
            .lock()
            .map_err(|_| "MST5 session storage lock is poisoned".to_string())? = Some(store);
        Ok(())
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeSessionSnapshot(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let result = (|| -> Result<String, String> {
        let values = session_storage()
            .lock()
            .map_err(|_| "MST5 session storage lock is poisoned".to_string())?;
        values
            .as_ref()
            .ok_or_else(|| "MST5 session storage is not initialized".to_string())?
            .snapshot_json()
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(snapshot) => match env.new_string(snapshot) {
            Ok(value) => value.into_raw(),
            Err(error) => {
                throw_io(&mut env, format!("cannot create session snapshot: {error}"));
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeReplaceSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    raw: JString<'_>,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        let raw = java_string(&mut env, raw)?;
        let mut values = session_storage()
            .lock()
            .map_err(|_| "MST5 session storage lock is poisoned".to_string())?;
        values
            .as_mut()
            .ok_or_else(|| "MST5 session storage is not initialized".to_string())?
            .replace_json(&raw)
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    device_model: JString<'_>,
    transport_mode: JString<'_>,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let endpoint = java_string(&mut env, endpoint)?;
        let supplied_public_key = java_string(&mut env, public_key)?;
        let device_model = java_string(&mut env, device_model)?;
        let transport_mode = java_string(&mut env, transport_mode)?;
        let public_key = compiled_server_public_key_b64().unwrap_or(&supplied_public_key);
        let messenger = MessengerCore::new(MessengerConfig::new(
            endpoint,
            public_key,
            device_model,
            TransportMode::parse(&transport_mode),
        ))
        .map_err(|error| error.to_string())?;
        let handle = i64::from(NEXT_CLIENT.fetch_add(1, Ordering::Relaxed));
        if handle <= 0 {
            return Err("MST5 native connection ID exhausted".to_string());
        }
        clients()
            .lock()
            .map_err(|_| "MST5 client registry is poisoned".to_string())?
            .insert(handle, Arc::new(NativeClient { messenger }));
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
            if let Err(error) = runtime.block_on(value.messenger.close()) {
                throw_io(&mut env, error);
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeCall(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: JString<'_>,
    frame_kind: jint,
    opcode: jint,
    timeout_ms: jint,
    input: JByteBuffer<'_>,
    input_len: jint,
    output: JByteBuffer<'_>,
) -> jlong {
    let result = (|| -> Result<u64, String> {
        if !(0..=u16::MAX as jint).contains(&opcode) {
            return Err("MST5 opcode is out of range".to_string());
        }
        if input_len < 0 {
            return Err("MST5 input length is negative".to_string());
        }
        let token = java_string(&mut env, token)?;
        let connection = client(handle)?;
        let input_capacity = env
            .get_direct_buffer_capacity(&input)
            .map_err(|error| format!("invalid direct MST5 input buffer: {error}"))?;
        let input_len = input_len as usize;
        if input_len > input_capacity {
            return Err("MST5 input exceeds direct buffer capacity".to_string());
        }
        let input_address = env
            .get_direct_buffer_address(&input)
            .map_err(|error| format!("invalid direct MST5 input buffer: {error}"))?;
        let payload = unsafe { std::slice::from_raw_parts(input_address, input_len) };
        let deadline_ms = unix_now_ms().saturating_add(timeout_ms.max(1) as u64);
        let response = runtime()?
            .block_on(connection.messenger.request_cbor(
                &token,
                frame_kind as u8,
                opcode as u16,
                payload,
                RequestOptions::default().with_deadline_ms(deadline_ms),
            ))
            .map_err(|error| error.to_string())?;
        let output_capacity = env
            .get_direct_buffer_capacity(&output)
            .map_err(|error| format!("invalid direct MST5 output buffer: {error}"))?;
        if response.payload.len() > output_capacity {
            return Err(format!(
                "MST5 response needs {} bytes, direct buffer has {}",
                response.payload.len(),
                output_capacity
            ));
        }
        let output_address = env
            .get_direct_buffer_address(&output)
            .map_err(|error| format!("invalid direct MST5 output buffer: {error}"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                response.payload.as_ptr(),
                output_address,
                response.payload.len(),
            );
        }
        Ok(((response.kind as u64) << 48)
            | ((response.status as u64) << 32)
            | response.payload.len() as u64)
    })();
    match result {
        Ok(value) => value as jlong,
        Err(error) => {
            throw_io(&mut env, error);
            -1
        }
    }
}

/// JSON command/event bridge used by the Android presentation layer.  The
/// Rust core owns endpoint selection, method-to-opcode routing and canonical
/// CBOR encoding; managed code only transfers a serializable view model.
#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeCommandJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    command: JString<'_>,
) -> jstring {
    let result = (|| -> Result<String, String> {
        let command = java_string(&mut env, command)?;
        let connection = client(handle)?;
        runtime()?
            .block_on(connection.messenger.command_json(&command))
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(response) => match env.new_string(response) {
            Ok(value) => value.into_raw(),
            Err(error) => {
                throw_io(
                    &mut env,
                    format!("cannot create messenger JSON response: {error}"),
                );
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDecodeImageFd(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    fd: jint,
    max_side: jint,
    max_pixels: jlong,
    output: JByteBuffer<'_>,
) -> jlong {
    let result = (|| -> Result<u64, String> {
        let file = duplicate_file(fd)?;
        let decoded = mst5_client::image::decode_image(
            file,
            max_side.max(1) as u32,
            max_pixels.max(1) as u64,
        )
        .map_err(|error| error.to_string())?;
        let required = decoded
            .argb
            .len()
            .saturating_mul(std::mem::size_of::<u32>());
        let capacity = env
            .get_direct_buffer_capacity(&output)
            .map_err(|error| format!("invalid direct image output buffer: {error}"))?;
        if required > capacity {
            return Err(format!(
                "decoded image needs {required} bytes, direct buffer has {capacity}"
            ));
        }
        let address = env
            .get_direct_buffer_address(&output)
            .map_err(|error| format!("invalid direct image output buffer: {error}"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(decoded.argb.as_ptr().cast::<u8>(), address, required);
        }
        Ok((u64::from(decoded.width) << 32) | u64::from(decoded.height))
    })();
    match result {
        Ok(value) => value as jlong,
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDecodeImage(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    input: JByteBuffer<'_>,
    input_len: jint,
    max_side: jint,
    max_pixels: jlong,
    output: JByteBuffer<'_>,
) -> jlong {
    let result = (|| -> Result<u64, String> {
        if input_len <= 0 {
            return Err("image input is empty".to_string());
        }
        let capacity = env
            .get_direct_buffer_capacity(&input)
            .map_err(|error| format!("invalid direct image input buffer: {error}"))?;
        if input_len as usize > capacity {
            return Err("image input exceeds direct buffer capacity".to_string());
        }
        let address = env
            .get_direct_buffer_address(&input)
            .map_err(|error| format!("invalid direct image input buffer: {error}"))?;
        let bytes = unsafe { std::slice::from_raw_parts(address, input_len as usize) };
        let decoded = mst5_client::image::decode_image_bytes(
            bytes,
            max_side.max(1) as u32,
            max_pixels.max(1) as u64,
        )
        .map_err(|error| error.to_string())?;
        let required = decoded
            .argb
            .len()
            .saturating_mul(std::mem::size_of::<u32>());
        let output_capacity = env
            .get_direct_buffer_capacity(&output)
            .map_err(|error| format!("invalid direct image output buffer: {error}"))?;
        if required > output_capacity {
            return Err(format!(
                "decoded image needs {required} bytes, direct buffer has {output_capacity}"
            ));
        }
        let output_address = env
            .get_direct_buffer_address(&output)
            .map_err(|error| format!("invalid direct image output buffer: {error}"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                decoded.argb.as_ptr().cast::<u8>(),
                output_address,
                required,
            );
        }
        Ok((u64::from(decoded.width) << 32) | u64::from(decoded.height))
    })();
    match result {
        Ok(value) => value as jlong,
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativePrepareWebp(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    input: JByteArray<'_>,
    max_side: jint,
    square: jboolean,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let input = java_bytes(&mut env, input)?;
        mst5_client::image::prepare_webp(&input, max_side.max(1) as u32, square != JNI_FALSE)
            .map(|prepared| prepared.bytes)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(value) => value.into_raw(),
            Err(error) => {
                throw_io(
                    &mut env,
                    format!("cannot allocate WebP byte array: {error}"),
                );
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
    last_callback_ms: Mutex<u64>,
}

impl JavaProgress {
    fn new(
        env: &mut JNIEnv<'_>,
        observer: JObject<'_>,
        total: u64,
    ) -> Result<Option<Arc<Self>>, String> {
        if observer.is_null() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self {
            vm: env
                .get_java_vm()
                .map_err(|error| format!("cannot access Java VM: {error}"))?,
            observer: env
                .new_global_ref(observer)
                .map_err(|error| format!("cannot retain transfer observer: {error}"))?,
            total,
            last_callback_ms: Mutex::new(0),
        })))
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
        let now = unix_now_ms();
        let mut previous = self
            .last_callback_ms
            .lock()
            .map_err(|_| io::Error::other("media progress lock poisoned"))?;
        let terminal = completed == 0 || completed >= self.total;
        if !terminal && now.saturating_sub(*previous) < 125 {
            return Ok(());
        }
        *previous = now;
        drop(previous);
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
    progress: Option<Arc<JavaProgress>>,
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
    progress: Option<Arc<JavaProgress>>,
    completed: u64,
}

struct BatchProgressReader<R> {
    inner: R,
    progress: Arc<JavaProgress>,
    aggregate: Arc<Mutex<u64>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for BatchProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let completed = *self
            .aggregate
            .lock()
            .map_err(|_| io::Error::other("media batch progress lock poisoned"))?;
        if let Err(error) = self.progress.update(completed) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let delta = (buffer.filled().len() - before) as u64;
                let completed = {
                    let mut aggregate = self
                        .aggregate
                        .lock()
                        .map_err(|_| io::Error::other("media batch progress lock poisoned"))?;
                    *aggregate = aggregate.saturating_add(delta);
                    *aggregate
                };
                if let Err(error) = self.progress.update(completed) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
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

fn java_string_array(
    env: &mut JNIEnv<'_>,
    values: &JObjectArray<'_>,
) -> Result<Vec<String>, String> {
    let length = env
        .get_array_length(values)
        .map_err(|error| format!("invalid Java string array: {error}"))?;
    let mut result = Vec::with_capacity(length as usize);
    for index in 0..length {
        let value = env
            .get_object_array_element(values, index)
            .map_err(|error| format!("invalid Java string array element: {error}"))?;
        result.push(java_string(env, JString::from(value))?);
    }
    Ok(result)
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
            progress: progress.clone(),
            completed: 0,
        };
        if let Some(progress) = &progress {
            progress.update(0).map_err(|error| error.to_string())?;
        }
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeUploadE2E(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    plaintext_size: jlong,
    fd: jint,
    identity_handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    observer: JObject<'_>,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        if plaintext_size < 0 || fd < 0 {
            return Err("invalid E2E media source".to_string());
        }
        let peer: [u8; 32] = java_bytes(&mut env, peer)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let identity = identity(identity_handle)?;
        let progress = JavaProgress::new(&mut env, observer, plaintext_size as u64)?;
        let file = duplicate_file(fd)?;
        let mut source = ProgressReader {
            inner: tokio::fs::File::from_std(file),
            progress: progress.clone(),
            completed: 0,
        };
        if let Some(progress) = &progress {
            progress.update(0).map_err(|error| error.to_string())?;
        }
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .upload_media_e2e(
                        &file_id,
                        plaintext_size as u64,
                        &mut source,
                        &identity,
                        peer,
                        &from,
                        &to,
                    )
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeUploadBatch(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoints: JObjectArray<'_>,
    public_keys: JObjectArray<'_>,
    tickets: JObjectArray<'_>,
    file_ids: JObjectArray<'_>,
    sizes: JLongArray<'_>,
    fds: JIntArray<'_>,
    observer: JObject<'_>,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        let endpoints = java_string_array(&mut env, &endpoints)?;
        let public_keys = java_string_array(&mut env, &public_keys)?;
        let tickets = java_string_array(&mut env, &tickets)?;
        let file_ids = java_string_array(&mut env, &file_ids)?;
        let count = endpoints.len();
        if count == 0
            || count > 64
            || public_keys.len() != count
            || tickets.len() != count
            || file_ids.len() != count
            || env
                .get_array_length(&sizes)
                .map_err(|error| error.to_string())? as usize
                != count
            || env
                .get_array_length(&fds)
                .map_err(|error| error.to_string())? as usize
                != count
        {
            return Err("media batch arrays must have the same 1..64 length".to_string());
        }
        let mut sizes_raw = vec![0_i64; count];
        let mut fds_raw = vec![0_i32; count];
        env.get_long_array_region(&sizes, 0, &mut sizes_raw)
            .map_err(|error| format!("invalid media size array: {error}"))?;
        env.get_int_array_region(&fds, 0, &mut fds_raw)
            .map_err(|error| format!("invalid media descriptor array: {error}"))?;
        if sizes_raw.iter().any(|value| *value < 0) || fds_raw.iter().any(|value| *value < 0) {
            return Err("media batch contains an invalid size or descriptor".to_string());
        }
        let total = sizes_raw
            .iter()
            .try_fold(0_u64, |total, value| total.checked_add(*value as u64))
            .ok_or_else(|| "media batch total size overflow".to_string())?;
        let progress = JavaProgress::new(&mut env, observer, total)?;
        let progress = progress.ok_or_else(|| "media batch observer is required".to_string())?;
        progress.update(0).map_err(|error| error.to_string())?;
        let files = fds_raw
            .into_iter()
            .map(duplicate_file)
            .collect::<Result<Vec<_>, _>>()?;
        let transfers = endpoints
            .into_iter()
            .zip(public_keys)
            .zip(tickets)
            .zip(file_ids)
            .zip(sizes_raw)
            .zip(files)
            .map(
                |(((((endpoint, public_key), ticket), file_id), size), file)| {
                    (endpoint, public_key, ticket, file_id, size as u64, file)
                },
            )
            .collect::<Vec<_>>();
        runtime()?
            .block_on(async move {
                let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
                let aggregate = Arc::new(Mutex::new(0_u64));
                let mut tasks = tokio::task::JoinSet::new();
                for (endpoint, public_key, ticket, file_id, size, file) in transfers {
                    let semaphore = semaphore.clone();
                    let aggregate = aggregate.clone();
                    let progress = progress.clone();
                    tasks.spawn(async move {
                        let _permit = semaphore
                            .acquire_owned()
                            .await
                            .map_err(|_| io::Error::other("media batch cancelled"))?;
                        let mut source = BatchProgressReader {
                            inner: tokio::fs::File::from_std(file),
                            progress,
                            aggregate,
                        };
                        let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                        let result = client.upload_media(&file_id, size, &mut source).await;
                        let _ = client.close().await;
                        result
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tasks.abort_all();
                            return Err(error);
                        }
                        Err(error) => {
                            tasks.abort_all();
                            return Err(io::Error::other(error.to_string()));
                        }
                    }
                }
                progress.update(total)
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
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDownloadE2E(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    expected_encrypted_size: jlong,
    fd: jint,
    identity_handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    observer: JObject<'_>,
) -> jlong {
    let result = (|| -> Result<u64, String> {
        if expected_encrypted_size < 0 || fd < 0 {
            return Err("invalid E2E media target".to_string());
        }
        let peer: [u8; 32] = java_bytes(&mut env, peer)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let identity = identity(identity_handle)?;
        let file = duplicate_file(fd)?;
        let mut target = ProgressWriter {
            inner: tokio::fs::File::from_std(file),
            progress: JavaProgress::new(&mut env, observer, 0)?,
            completed: 0,
        };
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .download_media_e2e(
                        &file_id,
                        expected_encrypted_size as u64,
                        &mut target,
                        &identity,
                        peer,
                        &from,
                        &to,
                    )
                    .await;
                let _ = client.close().await;
                result
            })
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => value as jlong,
        Err(error) => {
            throw_io(&mut env, error);
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeDownloadE2EBytes(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint: JString<'_>,
    public_key: JString<'_>,
    ticket: JString<'_>,
    file_id: JString<'_>,
    expected_encrypted_size: jlong,
    max_bytes: jint,
    identity_handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        if expected_encrypted_size < 0 || max_bytes < 1 {
            return Err("invalid E2E in-memory media size".to_string());
        }
        let peer: [u8; 32] = java_bytes(&mut env, peer)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let (endpoint, public_key, ticket, file_id) =
            transfer_strings(&mut env, endpoint, public_key, ticket, file_id)?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let identity = identity(identity_handle)?;
        let mut target = MemoryWriter {
            bytes: Vec::with_capacity((max_bytes as usize).min(256 * 1024)),
            limit: max_bytes as usize,
        };
        runtime()?
            .block_on(async {
                let client = Client::connect_media(&endpoint, &public_key, &ticket).await?;
                let result = client
                    .download_media_e2e(
                        &file_id,
                        expected_encrypted_size as u64,
                        &mut target,
                        &identity,
                        peer,
                        &from,
                        &to,
                    )
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
            store.load().and_then(|value| {
                value.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "E2E identity not found")
                })
            })
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
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EClose(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if let Ok(mut values) = identities().lock() {
        values.remove(&handle);
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ERemove(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) {
    let result = java_string(&mut env, path).and_then(|path| {
        IdentityStore::new(path)
            .remove()
            .map_err(|error| error.to_string())
    });
    if let Err(error) = result {
        throw_io(&mut env, error);
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EPublicKey(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    match identity(handle) {
        Ok(value) => env
            .byte_array_from_slice(&value.public_key())
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EFingerprint(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    match identity(handle) {
        Ok(value) => env
            .byte_array_from_slice(value.fingerprint().as_bytes())
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EPublicFingerprint(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    public_key: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<String, String> {
        let public_key: [u8; 32] = java_bytes(&mut env, public_key)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        Ok(mst5_client::e2e::fingerprint(&public_key))
    })();
    match result {
        Ok(value) => env
            .byte_array_from_slice(value.as_bytes())
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ESeal(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    plaintext: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let peer: [u8; 32] = java_bytes(&mut env, peer)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let plaintext = java_bytes(&mut env, plaintext)?;
        let value = identity(handle)?
            .seal(peer, &from, &to, &plaintext)
            .map_err(|error| error.to_string())?;
        let mut encoded = Vec::with_capacity(25 + value.ciphertext.len());
        encoded.push(value.version);
        encoded.extend_from_slice(&value.nonce);
        encoded.extend_from_slice(&value.ciphertext);
        Ok(encoded)
    })();
    match result {
        Ok(value) => env
            .byte_array_from_slice(&value)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EDecrypt(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    encoded: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let peer: [u8; 32] = java_bytes(&mut env, peer)?
            .try_into()
            .map_err(|_| "E2E public key must be 32 bytes".to_string())?;
        let from = java_string(&mut env, from)?;
        let to = java_string(&mut env, to)?;
        let encoded = java_bytes(&mut env, encoded)?;
        if encoded.len() < 41 || !matches!(encoded[0], LEGACY_ENVELOPE_VERSION | ENVELOPE_VERSION) {
            return Err("unsupported E2E envelope version; update the application".to_string());
        }
        let value = Envelope {
            version: encoded[0],
            nonce: encoded[1..25].try_into().unwrap(),
            ciphertext: encoded[25..].to_vec(),
        };
        identity(handle)?
            .open(peer, &from, &to, &value)
            .map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => env
            .byte_array_from_slice(&value)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EMediaSeal(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    file_id: JString<'_>,
    plaintext: JByteArray<'_>,
) -> jbyteArray {
    let _ = (handle, peer, from, to, file_id, plaintext);
    throw_io(
        &mut env,
        "E2E media V1 was removed; use descriptor streaming",
    );
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EMediaDecrypt(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    peer: JByteArray<'_>,
    from: JString<'_>,
    to: JString<'_>,
    file_id: JString<'_>,
    encoded: JByteArray<'_>,
) -> jbyteArray {
    let _ = (handle, peer, from, to, file_id, encoded);
    throw_io(
        &mut env,
        "E2E media V1 was removed; use descriptor streaming",
    );
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2EBackup(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    password: JString<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        let password = java_string(&mut env, password)?;
        let value = identity(handle)?
            .backup(&password)
            .map_err(|error| error.to_string())?;
        let mut encoded = Vec::with_capacity(41 + value.ciphertext.len());
        encoded.push(value.version);
        encoded.extend_from_slice(&value.salt);
        encoded.extend_from_slice(&value.nonce);
        encoded.extend_from_slice(&value.ciphertext);
        Ok(encoded)
    })();
    match result {
        Ok(value) => env
            .byte_array_from_slice(&value)
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            throw_io(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeE2ERestore(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
    password: JString<'_>,
    encoded: JByteArray<'_>,
) -> jlong {
    let result = (|| -> Result<i64, String> {
        let path = java_string(&mut env, path)?;
        let password = java_string(&mut env, password)?;
        let encoded = java_bytes(&mut env, encoded)?;
        if encoded.len() != 89 || encoded[0] != 2 {
            return Err("invalid E2E backup v2".to_string());
        }
        let backup = Backup {
            version: encoded[0],
            salt: encoded[1..17].try_into().unwrap(),
            nonce: encoded[17..41].try_into().unwrap(),
            ciphertext: encoded[41..].to_vec(),
        };
        let value = Identity::restore(&backup, &password).map_err(|error| error.to_string())?;
        IdentityStore::new(path)
            .save(&value)
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
        Err(error) => {
            throw_io(&mut env, error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_rs_ove_crypt_proto_NativeMst5_nativeInstallCrashHandler(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) {
    let result = (|| -> Result<(), String> {
        let path = java_string(&mut env, path)?;
        let c_path = std::ffi::CString::new(path.clone())
            .map_err(|_| "invalid crash report path".to_string())?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "cannot open native crash report: {}",
                io::Error::last_os_error()
            ));
        }
        let previous_fd = CRASH_FD.swap(fd, Ordering::SeqCst);
        if previous_fd >= 0 {
            unsafe {
                libc::close(previous_fd);
            }
        }
        for signal in [
            libc::SIGABRT,
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGFPE,
        ] {
            unsafe {
                libc::signal(
                    signal,
                    native_crash_signal as *const () as libc::sighandler_t,
                );
            }
        }
        std::panic::set_hook(Box::new(move |info| {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(file, "[OVE_ANDROID_CRASH_V1]\nSource: rust-panic\n{info}");
                let _ = file.sync_all();
            }
        }));
        Ok(())
    })();
    if let Err(error) = result {
        throw_io(&mut env, error);
    }
}
