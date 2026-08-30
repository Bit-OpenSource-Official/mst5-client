use mst5_client::e2e::{Backup, Envelope, Identity, IdentityStore, BACKUP_VERSION, ENVELOPE_VERSION, LEGACY_ENVELOPE_VERSION};
use mst5_client::{compiled_server_public_key_b64, Client, RequestOptions};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;
use tokio::io::{AsyncRead, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = 1;
const IO_ERROR: i32 = 2;
const NOT_FOUND: i32 = 3;
const PANIC: i32 = 255;

struct SliceReader<'a> { data: &'a [u8], offset: usize }
impl AsyncRead for SliceReader<'_> {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let remaining = &self.data[self.offset..];
        if remaining.is_empty() { return Poll::Ready(Ok(())); }
        let count = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

#[repr(C)]
pub struct Mst5Buffer {
    data: *mut u8,
    len: usize,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static CLIENTS: OnceLock<Mutex<HashMap<u64, Client>>> = OnceLock::new();
static IDENTITIES: OnceLock<Mutex<HashMap<u64, Arc<Identity>>>> = OnceLock::new();
static NEXT_HANDLE: Mutex<u64> = Mutex::new(1);

fn runtime() -> Result<&'static Runtime, String> {
    RUNTIME
        .get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

fn clients() -> &'static Mutex<HashMap<u64, Client>> {
    CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn identities() -> &'static Mutex<HashMap<u64, Arc<Identity>>> {
    IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_error(error: impl ToString) {
    let clean = error.to_string().replace('\0', " ");
    LAST_ERROR.with(|slot| *slot.borrow_mut() = CString::new(clean).unwrap_or_else(|_| CString::new("unknown error").unwrap()));
}

fn guard(action: impl FnOnce() -> Result<(), (i32, String)>) -> i32 {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => {
            set_error("");
            OK
        }
        Ok(Err((code, error))) => {
            set_error(error);
            code
        }
        Err(_) => {
            set_error("panic crossed the MST5 C ABI boundary");
            PANIC
        }
    }
}

unsafe fn text<'a>(value: *const c_char, name: &str) -> Result<&'a str, (i32, String)> {
    if value.is_null() {
        return Err((INVALID_ARGUMENT, format!("{name} is null")));
    }
    CStr::from_ptr(value).to_str().map_err(|_| (INVALID_ARGUMENT, format!("{name} is not UTF-8")))
}

unsafe fn bytes<'a>(value: *const u8, len: usize, name: &str) -> Result<&'a [u8], (i32, String)> {
    if len == 0 {
        return Ok(&[]);
    }
    if value.is_null() {
        return Err((INVALID_ARGUMENT, format!("{name} is null")));
    }
    Ok(slice::from_raw_parts(value, len))
}

unsafe fn output(out: *mut Mst5Buffer, value: Vec<u8>) -> Result<(), (i32, String)> {
    if out.is_null() {
        return Err((INVALID_ARGUMENT, "output buffer is null".to_string()));
    }
    let mut value = value.into_boxed_slice();
    let buffer = Mst5Buffer { data: value.as_mut_ptr(), len: value.len() };
    std::mem::forget(value);
    ptr::write(out, buffer);
    Ok(())
}

fn next_handle() -> Result<u64, (i32, String)> {
    let mut next = NEXT_HANDLE.lock().map_err(|_| io_error("native handle registry poisoned"))?;
    let handle = *next;
    if handle == 0 {
        return Err((IO_ERROR, "native handle space exhausted".to_string()));
    }
    *next = handle.checked_add(1).unwrap_or(0);
    Ok(handle)
}

fn io_error(error: impl ToString) -> (i32, String) {
    (IO_ERROR, error.to_string())
}

fn identity(handle: u64) -> Result<Arc<Identity>, (i32, String)> {
    identities().lock().map_err(|_| io_error("identity registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "identity handle not found".to_string()))
}

#[no_mangle]
pub extern "C" fn mst5_abi_version() -> u32 { 1 }

#[no_mangle]
pub extern "C" fn mst5_version() -> *const c_char { b"0.5.0\0".as_ptr().cast() }

#[no_mangle]
pub extern "C" fn mst5_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn mst5_buffer_free(buffer: Mst5Buffer) {
    if !buffer.data.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len)));
    }
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_connect(endpoint: *const c_char, key: *const c_char, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() { return Err((INVALID_ARGUMENT, "out_client is null".to_string())); }
        let endpoint = text(endpoint, "endpoint")?;
        let key = text(key, "server_public_key_b64")?;
        let client = runtime().map_err(io_error)?.block_on(Client::connect(endpoint, key)).map_err(io_error)?;
        let handle = next_handle()?;
        clients().lock().map_err(|_| io_error("client registry poisoned"))?.insert(handle, client);
        ptr::write(out, handle);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_connect_compiled(endpoint: *const c_char, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() { return Err((INVALID_ARGUMENT, "out_client is null".to_string())); }
        let endpoint = text(endpoint, "endpoint")?;
        let key = compiled_server_public_key_b64().map_err(io_error)?;
        let client = runtime().map_err(io_error)?.block_on(Client::connect(endpoint, key)).map_err(io_error)?;
        let handle = next_handle()?;
        clients().lock().map_err(|_| io_error("client registry poisoned"))?.insert(handle, client);
        ptr::write(out, handle);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_connect_media(endpoint: *const c_char, key: *const c_char, ticket: *const c_char, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() { return Err((INVALID_ARGUMENT, "out_client is null".to_string())); }
        let endpoint = text(endpoint, "endpoint")?;
        let key = text(key, "server_public_key_b64")?;
        let ticket = text(ticket, "ticket")?;
        let client = runtime().map_err(io_error)?.block_on(Client::connect_media(endpoint, key, ticket)).map_err(io_error)?;
        let handle = next_handle()?;
        clients().lock().map_err(|_| io_error("client registry poisoned"))?.insert(handle, client);
        ptr::write(out, handle);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_authenticate(handle: u64, token: *const c_char) -> i32 {
    guard(|| {
        let token = text(token, "token")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        runtime().map_err(io_error)?.block_on(client.authenticate(token)).map_err(io_error)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_request(handle: u64, kind: u8, opcode: u16, payload: *const u8, payload_len: usize, deadline_ms: u64, out: *mut Mst5Buffer) -> i32 {
    mst5_client_request_inner(handle, kind, opcode, payload, payload_len, None, deadline_ms, out)
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_request_with_nonce(handle: u64, kind: u8, opcode: u16, payload: *const u8, payload_len: usize, nonce: *const u8, deadline_ms: u64, out: *mut Mst5Buffer) -> i32 {
    if nonce.is_null() { return INVALID_ARGUMENT; }
    let nonce = std::slice::from_raw_parts(nonce, 16);
    mst5_client_request_inner(handle, kind, opcode, payload, payload_len, Some(nonce), deadline_ms, out)
}

unsafe fn mst5_client_request_inner(handle: u64, kind: u8, opcode: u16, payload: *const u8, payload_len: usize, nonce: Option<&[u8]>, deadline_ms: u64, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let payload = bytes(payload, payload_len, "payload")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        let mut options = if deadline_ms == 0 {
            RequestOptions::default()
        } else {
            RequestOptions::default().with_deadline_ms(deadline_ms)
        };
        if let Some(nonce) = nonce {
            let nonce: [u8; 16] = nonce.try_into().map_err(|_| (INVALID_ARGUMENT, "nonce must be 16 bytes".to_string()))?;
            options = options.with_request_nonce(nonce);
        }
        let response = runtime().map_err(io_error)?.block_on(client.request_cbor_with_options(kind, opcode, payload, options)).map_err(io_error)?;
        let mut encoded = Vec::with_capacity(3 + response.payload.len());
        encoded.push(response.kind);
        encoded.extend_from_slice(&response.status.to_be_bytes());
        encoded.extend_from_slice(&response.payload);
        output(out, encoded)
    })
}

#[no_mangle]
pub extern "C" fn mst5_client_close(handle: u64) -> i32 {
    guard(|| {
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.remove(&handle).ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        runtime().map_err(io_error)?.block_on(client.close()).map_err(io_error)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_media_upload(handle: u64, file_id: *const c_char, data: *const u8, data_len: usize) -> i32 {
    guard(|| {
        let file_id = text(file_id, "file_id")?;
        let data = bytes(data, data_len, "data")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        let mut reader = SliceReader { data, offset: 0 };
        runtime().map_err(io_error)?.block_on(client.upload_media(file_id, data_len as u64, &mut reader)).map_err(io_error)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_media_download(handle: u64, file_id: *const c_char, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let file_id = text(file_id, "file_id")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        let size = runtime().map_err(io_error)?.block_on(client.media_stat(file_id)).map_err(io_error)?;
        let mut target = Vec::with_capacity(size as usize);
        runtime().map_err(io_error)?.block_on(client.download_media(file_id, size, &mut target)).map_err(io_error)?;
        output(out, target)
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_media_stat(handle: u64, file_id: *const c_char, out_size: *mut u64) -> i32 {
    guard(|| {
        if out_size.is_null() { return Err((INVALID_ARGUMENT, "out_size is null".to_string())); }
        let file_id = text(file_id, "file_id")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        let size = runtime().map_err(io_error)?.block_on(client.media_stat(file_id)).map_err(io_error)?;
        ptr::write(out_size, size);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_media_delete(handle: u64, file_id: *const c_char) -> i32 {
    guard(|| {
        let file_id = text(file_id, "file_id")?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        runtime().map_err(io_error)?.block_on(client.media_delete(file_id)).map_err(io_error)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_client_request_json(handle: u64, frame_kind: u8, opcode: u16, json_payload: *const c_char, deadline_ms: u64, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let json = text(json_payload, "json_payload")?;
        let value: serde_json::Value = serde_json::from_str(json).map_err(|error| (INVALID_ARGUMENT, format!("invalid JSON payload: {error}")))?;
        let payload = serde_cbor_encode(&value)?;
        let client = clients().lock().map_err(|_| io_error("client registry poisoned"))?.get(&handle).cloned().ok_or((NOT_FOUND, "client handle not found".to_string()))?;
        let options = if deadline_ms == 0 { RequestOptions::default() } else { RequestOptions::default().with_deadline_ms(deadline_ms) };
        let response = runtime().map_err(io_error)?.block_on(client.request_cbor_with_options(frame_kind, opcode, &payload, options)).map_err(io_error)?;
        let value: serde_json::Value = ciborium::from_reader(response.payload.as_slice()).map_err(|error| io_error(format!("decode response CBOR: {error}")))?;
        output(out, serde_json::to_vec(&value).map_err(io_error)?)
    })
}

fn serde_cbor_encode(value: &serde_json::Value) -> Result<Vec<u8>, (i32, String)> {
    let mut payload = Vec::new();
    ciborium::into_writer(value, &mut payload).map_err(|error| io_error(format!("encode request CBOR: {error}")))?;
    Ok(payload)
}

#[no_mangle]
pub unsafe extern "C" fn mst5_identity_open(path: *const c_char, create: i32, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() { return Err((INVALID_ARGUMENT, "out_identity is null".to_string())); }
        let store = IdentityStore::new(text(path, "private_store_path")?);
        let value = if create != 0 { store.load_or_create().map_err(io_error)? } else { store.load().map_err(io_error)?.ok_or((NOT_FOUND, "identity does not exist".to_string()))? };
        let handle = next_handle()?;
        identities().lock().map_err(|_| io_error("identity registry poisoned"))?.insert(handle, Arc::new(value));
        ptr::write(out, handle);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_identity_restore(path: *const c_char, password: *const c_char, backup: *const u8, backup_len: usize, out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() { return Err((INVALID_ARGUMENT, "out_identity is null".to_string())); }
        let path = text(path, "private_store_path")?;
        let password = text(password, "password")?;
        let restored = Identity::restore(&decode_backup(bytes(backup, backup_len, "backup")?)?, password).map_err(io_error)?;
        IdentityStore::new(path).save(&restored).map_err(io_error)?;
        let handle = next_handle()?;
        identities().lock().map_err(|_| io_error("identity registry poisoned"))?.insert(handle, Arc::new(restored));
        ptr::write(out, handle);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_identity_remove(path: *const c_char) -> i32 {
    guard(|| IdentityStore::new(text(path, "private_store_path")?).remove().map_err(io_error))
}

#[no_mangle]
pub extern "C" fn mst5_identity_close(handle: u64) -> i32 {
    guard(|| identities().lock().map_err(|_| io_error("identity registry poisoned"))?.remove(&handle).map(|_| ()).ok_or((NOT_FOUND, "identity handle not found".to_string())))
}

#[no_mangle]
pub unsafe extern "C" fn mst5_identity_public_key(handle: u64, out: *mut Mst5Buffer) -> i32 {
    guard(|| output(out, identity(handle)?.public_key().to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn mst5_identity_fingerprint(handle: u64, out: *mut Mst5Buffer) -> i32 {
    guard(|| output(out, identity(handle)?.fingerprint().into_bytes()))
}

#[no_mangle]
pub unsafe extern "C" fn mst5_e2e_seal(handle: u64, peer: *const u8, from: *const c_char, to: *const c_char, plaintext: *const u8, plaintext_len: usize, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let peer: [u8; 32] = bytes(peer, 32, "peer_public_key")?.try_into().unwrap();
        let envelope = identity(handle)?.seal(peer, text(from, "from_id")?, text(to, "to_id")?, bytes(plaintext, plaintext_len, "plaintext")?).map_err(io_error)?;
        output(out, encode_envelope(&envelope))
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_e2e_open(handle: u64, peer: *const u8, from: *const c_char, to: *const c_char, envelope: *const u8, envelope_len: usize, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let peer: [u8; 32] = bytes(peer, 32, "peer_public_key")?.try_into().unwrap();
        let plaintext = identity(handle)?.open(peer, text(from, "from_id")?, text(to, "to_id")?, &decode_envelope(bytes(envelope, envelope_len, "envelope")?)?).map_err(io_error)?;
        output(out, plaintext)
    })
}

#[no_mangle]
pub unsafe extern "C" fn mst5_e2e_backup(handle: u64, password: *const c_char, out: *mut Mst5Buffer) -> i32 {
    guard(|| {
        let backup = identity(handle)?.backup(text(password, "password")?).map_err(io_error)?;
        output(out, encode_backup(&backup))
    })
}

fn encode_envelope(value: &Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(25 + value.ciphertext.len());
    out.push(value.version);
    out.extend_from_slice(&value.nonce);
    out.extend_from_slice(&value.ciphertext);
    out
}

fn decode_envelope(value: &[u8]) -> Result<Envelope, (i32, String)> {
    if value.len() < 41 || !matches!(value[0], LEGACY_ENVELOPE_VERSION | ENVELOPE_VERSION) {
        return Err((INVALID_ARGUMENT, "unsupported E2E envelope".to_string()));
    }
    Ok(Envelope { version: value[0], nonce: value[1..25].try_into().unwrap(), ciphertext: value[25..].to_vec() })
}

fn encode_backup(value: &Backup) -> Vec<u8> {
    let mut out = Vec::with_capacity(41 + value.ciphertext.len());
    out.push(value.version);
    out.extend_from_slice(&value.salt);
    out.extend_from_slice(&value.nonce);
    out.extend_from_slice(&value.ciphertext);
    out
}

fn decode_backup(value: &[u8]) -> Result<Backup, (i32, String)> {
    if value.len() != 89 || value[0] != BACKUP_VERSION { return Err((INVALID_ARGUMENT, "invalid E2E backup".to_string())); }
    Ok(Backup { version: value[0], salt: value[1..17].try_into().unwrap(), nonce: value[17..41].try_into().unwrap(), ciphertext: value[41..].to_vec() })
}
