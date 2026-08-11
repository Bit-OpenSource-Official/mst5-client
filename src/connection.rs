use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{broadcast, mpsc, Mutex, OwnedSemaphorePermit, Semaphore};

const MAX_IN_FLIGHT: usize = 64;
const RESPONSE_QUEUE: usize = 128;
const EVENT_QUEUE: usize = 128;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

type PendingSender = mpsc::Sender<Result<Frame, String>>;

pub(super) struct Mst5Connection {
    writer: Mutex<WriterState>,
    pending: Mutex<HashMap<u64, PendingSender>>,
    events: broadcast::Sender<Response>,
    closed: AtomicBool,
    inflight: Arc<Semaphore>,
    write_timeout: Duration,
}

struct WriterState {
    stream: OwnedWriteHalf,
    cipher: CipherState,
    handshake_hash: [u8; 32],
    next_id: u64,
}

pub(super) struct PendingRequest {
    connection: Arc<Mst5Connection>,
    id: u64,
    receiver: mpsc::Receiver<Result<Frame, String>>,
    active: bool,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct StreamHandle {
    connection: Arc<Mst5Connection>,
    id: u64,
    receiver: Mutex<mpsc::Receiver<Result<Frame, String>>>,
    active: AtomicBool,
    _permit: OwnedSemaphorePermit,
}

impl Mst5Connection {
    pub(super) fn start(stream: TcpStream, session: Session, write_timeout: Duration) -> Arc<Self> {
        let (reader, writer) = stream.into_split();
        let (events, _) = broadcast::channel(EVENT_QUEUE);
        let connection = Arc::new(Self {
            writer: Mutex::new(WriterState {
                stream: writer,
                cipher: session.seal,
                handshake_hash: session.handshake_hash,
                next_id: 1,
            }),
            pending: Mutex::new(HashMap::new()),
            events,
            closed: AtomicBool::new(false),
            inflight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            write_timeout,
        });
        let weak = Arc::downgrade(&connection);
        tokio::spawn(reader_loop(
            weak,
            reader,
            session.open,
            session.handshake_hash,
        ));
        let weak = Arc::downgrade(&connection);
        tokio::spawn(keepalive_loop(weak));
        connection
    }

    pub(super) async fn begin(
        self: &Arc<Self>,
        kind: u8,
        code: u16,
        request_nonce: [u8; 16],
        deadline_ms: u64,
        payload: Vec<u8>,
    ) -> io::Result<PendingRequest> {
        let wait_timeout = self.stage_timeout(deadline_ms)?;
        let permit = tokio::time::timeout(wait_timeout, self.inflight.clone().acquire_owned())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MST5 request timed out waiting for an in-flight slot",
                )
            })?
            .map_err(|_| closed_error())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }

        let (sender, receiver) = mpsc::channel(RESPONSE_QUEUE);
        let wait_timeout = self.stage_timeout(deadline_ms)?;
        let mut writer = tokio::time::timeout(wait_timeout, self.writer.lock())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MST5 request timed out waiting for the record writer",
                )
            })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let id = writer.next_id;
        if id == 0 || id == u64::MAX {
            return Err(invalid_data(
                "MST5 request ID space exhausted; reconnect required",
            ));
        }
        writer.next_id += 1;
        let frame = Frame::request(kind, code, id, request_nonce, deadline_ms, payload)?;
        self.pending.lock().await.insert(id, sender);
        let mut pending = PendingRequest {
            connection: self.clone(),
            id,
            receiver,
            active: true,
            _permit: permit,
        };
        let wait_timeout = self.stage_timeout(deadline_ms)?;
        if let Err(error) = io_timeout(
            wait_timeout,
            "MST5 request timed out while writing",
            write_frame_locked(&mut writer, &frame, self.write_timeout),
        )
        .await
        {
            pending.remove().await;
            drop(writer);
            self.fail(format!("MST5 write failed: {error}")).await;
            return Err(error);
        }
        drop(writer);
        Ok(pending)
    }

    pub(super) async fn request(
        self: &Arc<Self>,
        kind: u8,
        code: u16,
        request_nonce: [u8; 16],
        deadline_ms: u64,
        payload: Vec<u8>,
        timeout_duration: Duration,
    ) -> io::Result<Frame> {
        let mut pending = self
            .begin(kind, code, request_nonce, deadline_ms, payload)
            .await?;
        let response_timeout = if deadline_ms == 0 {
            timeout_duration
        } else {
            deadline_timeout(deadline_ms, timeout_duration)?
        };
        match pending.recv(response_timeout).await {
            Ok(frame) => Ok(frame),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                pending.cancel().await;
                Err(error)
            }
            Err(error) => {
                pending.remove().await;
                Err(error)
            }
        }
    }

    pub(super) async fn begin_stream(
        self: &Arc<Self>,
        code: u16,
        payload: Vec<u8>,
        deadline_ms: u64,
    ) -> io::Result<StreamHandle> {
        let wait_timeout = self.stage_timeout(deadline_ms)?;
        let permit = tokio::time::timeout(wait_timeout, self.inflight.clone().acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MST5 stream slot timed out"))?
            .map_err(|_| closed_error())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let (sender, receiver) = mpsc::channel(RESPONSE_QUEUE);
        let wait_timeout = self.stage_timeout(deadline_ms)?;
        let mut writer = tokio::time::timeout(wait_timeout, self.writer.lock())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MST5 stream timed out waiting for the record writer",
                )
            })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let id = writer.next_id;
        if id == 0 || id == u64::MAX {
            return Err(invalid_data(
                "MST5 request ID space exhausted; reconnect required",
            ));
        }
        writer.next_id += 1;
        self.pending.lock().await.insert(id, sender);
        let frame = Frame::request(kind::STREAM_OPEN, code, id, [0; 16], deadline_ms, payload)?;
        if let Err(error) = write_frame_locked(&mut writer, &frame, self.write_timeout).await {
            self.pending.lock().await.remove(&id);
            return Err(error);
        }
        Ok(StreamHandle {
            connection: self.clone(),
            id,
            receiver: Mutex::new(receiver),
            active: AtomicBool::new(true),
            _permit: permit,
        })
    }

    pub(super) fn subscribe(&self) -> EventReceiver {
        EventReceiver {
            receiver: self.events.subscribe(),
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn stage_timeout(&self, deadline_ms: u64) -> io::Result<Duration> {
        deadline_timeout(deadline_ms, self.write_timeout)
    }

    pub(super) async fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = {
            let mut writer = self.writer.lock().await;
            write_close_locked(&mut writer, self.write_timeout).await
        };
        self.fail_pending("MST5 client closed the connection").await;
        result
    }

    async fn write_control(&self, frame: &Frame) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let mut writer = self.writer.lock().await;
        write_frame_locked(&mut writer, frame, self.write_timeout).await
    }

    async fn remove_pending(&self, id: u64) {
        self.pending.lock().await.remove(&id);
    }

    async fn cancel(&self, id: u64) {
        self.remove_pending(id).await;
        if let Ok(frame) = Frame::new(kind::CANCEL, 0, id, Vec::new()) {
            let _ = self.write_control(&frame).await;
        }
    }

    async fn fail(&self, message: String) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.fail_pending(&message).await;
    }

    async fn fail_pending(&self, message: &str) {
        let pending = std::mem::take(&mut *self.pending.lock().await);
        for (_, sender) in pending {
            let _ = sender.send(Err(message.to_string())).await;
        }
    }

    async fn dispatch(&self, frame: Frame) -> io::Result<()> {
        if frame.kind == kind::PING {
            return self
                .write_control(&Frame::new(kind::PONG, 0, frame.id, Vec::new())?)
                .await;
        }
        if !matches!(
            frame.kind,
            kind::RESULT
                | kind::EVENT_BATCH
                | kind::ACK
                | kind::ERROR
                | kind::PONG
                | kind::STREAM_DATA
                | kind::STREAM_END
                | kind::STREAM_ABORT
        ) {
            return Err(invalid_data("unexpected MST5 server frame"));
        }

        let terminal = matches!(
            frame.kind,
            kind::RESULT
                | kind::EVENT_BATCH
                | kind::ERROR
                | kind::PONG
                | kind::STREAM_END
                | kind::STREAM_ABORT
        );
        let sender = {
            let mut pending = self.pending.lock().await;
            if terminal {
                pending.remove(&frame.id)
            } else {
                pending.get(&frame.id).cloned()
            }
        };
        if let Some(sender) = sender {
            let _ = sender.send(Ok(frame)).await;
            return Ok(());
        }
        if frame.kind == kind::EVENT_BATCH {
            let _ = self.events.send(Response::from_frame(frame));
        }
        // Late replies after timeout/CANCEL are valid and intentionally ignored.
        Ok(())
    }
}

impl StreamHandle {
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    pub(super) async fn recv(&self, duration: Duration) -> io::Result<Frame> {
        let mut receiver = self.receiver.lock().await;
        match tokio::time::timeout(duration, receiver.recv()).await {
            Ok(Some(Ok(frame))) => Ok(frame),
            Ok(Some(Err(message))) => Err(io::Error::new(io::ErrorKind::ConnectionReset, message)),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MST5 stream closed",
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MST5 stream read timed out",
            )),
        }
    }

    pub(super) async fn send(&self, payload: Vec<u8>) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        self.connection
            .write_control(&Frame::new(kind::STREAM_DATA, 0, self.id, payload)?)
            .await
    }

    pub(super) async fn close(&self) -> io::Result<()> {
        if !self.active.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self
            .connection
            .write_control(&Frame::new(kind::STREAM_END, 200, self.id, Vec::new())?)
            .await;
        self.connection.remove_pending(self.id).await;
        result
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        let connection = self.connection.clone();
        let id = self.id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Ok(frame) = Frame::new(kind::STREAM_ABORT, 499, id, Vec::new()) {
                    let _ = connection.write_control(&frame).await;
                }
                connection.remove_pending(id).await;
            });
        }
    }
}

impl PendingRequest {
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    pub(super) async fn recv(&mut self, duration: Duration) -> io::Result<Frame> {
        match tokio::time::timeout(duration, self.receiver.recv()).await {
            Ok(Some(Ok(frame))) => {
                if is_terminal_response(frame.kind) {
                    self.active = false;
                }
                Ok(frame)
            }
            Ok(Some(Err(message))) => {
                self.active = false;
                Err(io::Error::new(io::ErrorKind::ConnectionReset, message))
            }
            Ok(None) => {
                self.active = false;
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MST5 response channel closed",
                ))
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MST5 request timed out",
            )),
        }
    }

    pub(super) async fn send(&self, kind: u8, code: u16, payload: Vec<u8>) -> io::Result<()> {
        self.connection
            .write_control(&Frame::new(kind, code, self.id, payload)?)
            .await
    }

    pub(super) async fn abort(&mut self, status: u16) {
        if !self.active {
            return;
        }
        let _ = self.send(kind::STREAM_ABORT, status, Vec::new()).await;
        self.remove().await;
    }

    pub(super) async fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.connection.cancel(self.id).await;
        self.active = false;
    }

    pub(super) async fn remove(&mut self) {
        if !self.active {
            return;
        }
        self.connection.remove_pending(self.id).await;
        self.active = false;
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let connection = self.connection.clone();
        let id = self.id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                connection.cancel(id).await;
            });
        }
    }
}

fn is_terminal_response(kind: u8) -> bool {
    matches!(
        kind,
        kind::RESULT
            | kind::EVENT_BATCH
            | kind::ERROR
            | kind::PONG
            | kind::STREAM_END
            | kind::STREAM_ABORT
    )
}

async fn reader_loop(
    connection: Weak<Mst5Connection>,
    mut reader: OwnedReadHalf,
    mut cipher: CipherState,
    handshake_hash: [u8; 32],
) {
    loop {
        let frame = match read_frame(&mut reader, &mut cipher, &handshake_hash).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                if let Some(connection) = connection.upgrade() {
                    connection
                        .fail("MST5 server closed the connection".to_string())
                        .await;
                }
                return;
            }
            Err(error) => {
                if let Some(connection) = connection.upgrade() {
                    connection.fail(format!("MST5 read failed: {error}")).await;
                }
                return;
            }
        };
        let Some(connection) = connection.upgrade() else {
            return;
        };
        if let Err(error) = connection.dispatch(frame).await {
            connection
                .fail(format!("MST5 protocol error: {error}"))
                .await;
            return;
        }
    }
}

async fn keepalive_loop(connection: Weak<Mst5Connection>) {
    let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
    interval.tick().await;
    loop {
        interval.tick().await;
        let Some(connection) = connection.upgrade() else {
            return;
        };
        if connection.is_closed() {
            return;
        }
        if let Ok(ping) = Frame::new(kind::PING, 0, 0, Vec::new()) {
            if let Err(error) = connection.write_control(&ping).await {
                connection
                    .fail(format!("MST5 keepalive failed: {error}"))
                    .await;
                return;
            }
        }
    }
}

async fn write_frame_locked(
    writer: &mut WriterState,
    frame: &Frame,
    write_timeout: Duration,
) -> io::Result<()> {
    let encoded = frame.clone().encode()?;
    let record = seal_record(&mut writer.cipher, &writer.handshake_hash, 0, &encoded)?;
    io_timeout(
        write_timeout,
        "MST5 write timed out",
        writer
            .stream
            .write_all(&(record.len() as u32).to_be_bytes()),
    )
    .await?;
    io_timeout(
        write_timeout,
        "MST5 write timed out",
        writer.stream.write_all(&record),
    )
    .await?;
    io_timeout(write_timeout, "MST5 flush timed out", writer.stream.flush()).await
}

async fn write_close_locked(writer: &mut WriterState, write_timeout: Duration) -> io::Result<()> {
    let record = seal_record(&mut writer.cipher, &writer.handshake_hash, 1, &[])?;
    let result = async {
        io_timeout(
            write_timeout,
            "MST5 close timed out",
            writer
                .stream
                .write_all(&(record.len() as u32).to_be_bytes()),
        )
        .await?;
        io_timeout(
            write_timeout,
            "MST5 close timed out",
            writer.stream.write_all(&record),
        )
        .await?;
        io_timeout(
            write_timeout,
            "MST5 close flush timed out",
            writer.stream.flush(),
        )
        .await
    }
    .await;
    let _ = writer.stream.shutdown().await;
    result
}

fn seal_record(
    cipher: &mut CipherState,
    handshake_hash: &[u8; 32],
    content_type: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let plaintext = transport_plaintext(content_type, payload)?;
    cipher.check_limit(plaintext.len())?;
    let sequence = cipher.nonce;
    let frame_length = 8usize
        .checked_add(plaintext.len())
        .and_then(|value| value.checked_add(TAG_LEN))
        .ok_or_else(|| invalid_data("MST5 record length overflow"))?;
    let aad = record_aad(handshake_hash, frame_length, sequence)?;
    let ciphertext = aead_encrypt(&cipher.key, sequence, &aad, &plaintext)?;
    let mut record = Vec::with_capacity(frame_length);
    record.extend_from_slice(&sequence.to_be_bytes());
    record.extend_from_slice(&ciphertext);
    cipher.commit(plaintext.len(), handshake_hash)?;
    Ok(record)
}

async fn read_frame(
    reader: &mut OwnedReadHalf,
    cipher: &mut CipherState,
    handshake_hash: &[u8; 32],
) -> io::Result<Option<Frame>> {
    let mut size = [0u8; 4];
    reader.read_exact(&mut size).await?;
    let length = u32::from_be_bytes(size) as usize;
    if length < 8 + TAG_LEN || length > max_record_len() {
        return Err(invalid_data("invalid MST5 encrypted record length"));
    }
    let mut record = vec![0u8; length];
    reader.read_exact(&mut record).await?;
    let sequence = u64::from_be_bytes(
        record[..8]
            .try_into()
            .map_err(|_| invalid_data("invalid MST5 sequence"))?,
    );
    if sequence != cipher.nonce {
        return Err(invalid_data("MST5 encrypted record sequence mismatch"));
    }
    let plaintext_len = record.len() - 8 - TAG_LEN;
    cipher.check_limit(plaintext_len)?;
    let aad = record_aad(handshake_hash, record.len(), sequence)?;
    let plaintext = aead_decrypt(&cipher.key, sequence, &aad, &record[8..])?;
    let decoded = parse_transport_plaintext(&plaintext)?;
    cipher.commit(plaintext.len(), handshake_hash)?;
    match decoded {
        Record::Application(payload) => Frame::decode(&payload).map(Some),
        Record::Close => Ok(None),
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "MST5 connection is closed")
}
