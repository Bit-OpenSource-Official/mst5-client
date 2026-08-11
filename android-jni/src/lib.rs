use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use mst5_client::{kind, Client, ClientOptions, RequestOptions};
use std::collections::HashMap;
use std::io;
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;

const BRIDGE_VERSION: jint = 1;

struct NativeClient {
    client: Client,
    token: Mutex<Option<String>>,
}

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static CLIENTS: OnceLock<Mutex<HashMap<i64, Arc<NativeClient>>>> = OnceLock::new();
static NEXT_CLIENT: AtomicI32 = AtomicI32::new(1);

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
    frame_kind: jint,
    opcode: jint,
    request_nonce: JByteArray<'_>,
    deadline_ms: jlong,
    payload: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        if !(0..=u16::MAX as jint).contains(&opcode) {
            return Err("invalid MST5 opcode".to_string());
        }
        let token = java_string(&mut env, token)?;
        let nonce = java_bytes(&mut env, request_nonce)?;
        let payload = java_bytes(&mut env, payload)?;
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
        let mut options = RequestOptions::default();
        if frame_kind as u8 == kind::COMMAND {
            if nonce.len() != 16 {
                return Err("invalid MST5 command nonce".to_string());
            }
            let mut value = [0u8; 16];
            value.copy_from_slice(&nonce);
            options = options.with_request_nonce(value);
        }
        if deadline_ms > 0 {
            options = options.with_deadline_ms(deadline_ms as u64);
        }
        let response = runtime()?
            .block_on(connection.client.request_cbor_with_options(
                frame_kind as u8,
                opcode as u16,
                &payload,
                options,
            ))
            .map_err(|error| error.to_string())?;
        let mut encoded = Vec::with_capacity(3 + response.payload.len());
        encoded.push(response.kind);
        encoded.extend_from_slice(&response.status.to_be_bytes());
        encoded.extend_from_slice(&response.payload);
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
