//! MST5 over HTTP(S) client transport.
//!
//! The protocol purposely uses two independent HTTP/1.1 streams.  `up` carries
//! bytes written by MST5, and long-polled `down` responses carry bytes received
//! from MST5.  A short-lived loopback TCP connection lets the rest of the
//! client keep the same audited Noise and frame implementation as raw MST5.

use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{tcp::{OwnedReadHalf, OwnedWriteHalf}, TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream, TlsConnector};

const MAX_HTTP_HEAD: usize = 64 * 1024;
const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;
const UPLOAD_CHUNK: usize = 256 * 1024;
// The production edge currently uses the project CA below rather than a
// browser CA. Keep public WebPKI roots as well so independently hosted M5oH
// domains can use ordinary public certificates.
const OVE_PRODUCTION_CA_DER_B64: &str = "MIIFHzCCAwegAwIBAgIUfMPeVsx/AOHL2N4bA0mI2xeX8GMwDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUb3ZlLnJzIGxvY2FsIHRlc3QgQ0EwHhcNMjYwNzI5MTQxMjM4WhcNMzYwNzI2MTQxMjM4WjAfMR0wGwYDVQQDDBRvdmUucnMgbG9jYWwgdGVzdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALszQFeOXjlEWtwC5whUpCRIptscRIYijvPvdObPygESuvVUYLKxRoirHgGrERb4oakXtAbk6ce/TA4tHPMTLM1H2IvRtCwp+/ZCOJgPMa4RQ9eRXhAMupDIzsWQUtVbxUrZstfwAJ+UoLlZTUurR0orXK/jQ2CppqKDMc4eVY+gaCiXg04j9U+9PdqX8Tv0ga/WaSlOHXVmuCI3t6Ja/p2tAfdM5PwXud0by1byXMvl1xW6OA3vl1XMUrmoCuJI9AD+7ufhlxnn8JfHi2Qzg1+xEZeOSjvB7qa6mxPbAWbFwXIPbQXFZUgc1aXbe+huaocivYzdCCZD+WbsnBEFynpylGySZian88gVmjVmKOYTv43IqHRKI/2KhXk37wTy73UETQ77SWIXDrKWmAkQafNq0H2O7UrIr5uUryckcTrW8BbY0Cfg9ofO8FGHQ4PxLXTrDwdzXqeZax/HN00qJvYthrogcZTsNZcqVGk3drrpWbJj9C/xWA5tnULEnIgCIUwGY8MdHX3EzejoYSIGKxxYCiEHchehuMmcdWeR9Y64r/yAN+Gu3T1/mQblcu2kr0cb1qFfmZYS44jwZq7tHQk1NaXijn1YXhf6zFc1mvbbotxHX9lfvAI+139hG8IjwnazSogNaXADPEDdyGxlY36pVslPUF/QZhOeIc80+v1/AgMBAAGjUzBRMB0GA1UdDgQWBBQgS5Qsi0OqXLTQ1BVoVqoaUSgZ/jAfBgNVHSMEGDAWgBQgS5Qsi0OqXLTQ1BVoVqoaUSgZ/jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAU1RnkWBGH5LOTqxk+m48O9myi0VkQvN1svdolBsaf8c1OqgbJ0MjCL2HNy7X+l+tx/lcRMfX/rDGE2kfy6R6hy5hzfi2uvBTD97JKeDw3ftZl4k7uTINBf9NdbA3jtH+NiuXfvU79lOHzsilNpa+K5MrMzOSw4yR+4INSApD/GAlWN4hkT4ZjdHRKjej4w9QAXGRC+UJSaRDEs5b+wKnoYKQNt0FUgVReVcaNSWC8TorVma5zbF8U0slF3lB57QeiythYiHATqJh/1zQhpKvko6bxqcEbDTFJNgz8DWzrVlRcJILjABHdVNjS938bnSBWTNTrckFKdNmyu5+WKhIevciDoGVl8oC+tkVtKPQnI7AtKUFIpVqi+DCBXmTrYwLBngNChKRxiyjDUnSbO0pbtvSwpc4rlP9VnBmJr+DOqdunSKo9xp4C+gVNbUXfCw6cdGmRz9YYNMo1PMOArmipy+PEn1N9EZAIoBWmXc+Whm+szVtWGWf4/eMiRs+rR52+sfJIYZ9A2DZ9rrmxffj6ysmcUNi9GQNV29IXmQI6a6lulhQWyR7DjpxoIKyeBXiLav20JxvJszD4zKuXnJVrdr7tr2ksw04yMV9KI2nAl+a0wVgIqYMz/jare6FeCPDCOqQe3sFbtZ9kDBXHA1AVeH0DhiI6wa13tKDjo69QjA==";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    pub(crate) route: Option<String>,
}

impl Endpoint {
    pub(crate) fn host_header(&self) -> String {
        if (self.tls && self.port == 443) || (!self.tls && self.port == 80) {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

enum HttpStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for HttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

pub(crate) async fn open_loopback_bridge(endpoint: Endpoint, connect_timeout: Duration) -> io::Result<TcpStream> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else { return };
        let _ = bridge(stream, endpoint, connect_timeout).await;
    });
    timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "M5oH local bridge timed out"))?
}

async fn bridge(stream: TcpStream, endpoint: Endpoint, connect_timeout: Duration) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let session_id = random_session_id()?;
    // seq=0 creates the remote TCP connection before the local client writes
    // the Noise prologue. This avoids a race with its initial read.
    request(&endpoint, connect_timeout, &session_id, "up", 0, &[], false).await?;
    let (reader, writer) = stream.into_split();
    let mut upload = tokio::spawn(upload_loop(reader, endpoint.clone(), connect_timeout, session_id.clone()));
    let mut download = tokio::spawn(download_loop(writer, endpoint, connect_timeout, session_id));
    tokio::select! {
        result = &mut upload => {
            download.abort();
            let _ = download.await;
            result.map_err(join_error)?
        }
        result = &mut download => {
            upload.abort();
            let _ = upload.await;
            result.map_err(join_error)?
        }
    }
}

fn join_error(error: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("M5oH bridge task failed: {error}"))
}

async fn upload_loop(
    mut reader: OwnedReadHalf,
    endpoint: Endpoint,
    connect_timeout: Duration,
    session_id: String,
) -> io::Result<()> {
    let mut sequence = 1u64;
    let mut buffer = vec![0u8; UPLOAD_CHUNK];
    loop {
        let count = reader.read(&mut buffer).await?;
        let eof = count == 0;
        request(&endpoint, connect_timeout, &session_id, "up", sequence, &buffer[..count], eof).await?;
        sequence = sequence.checked_add(1).ok_or_else(|| io::Error::other("M5oH upload sequence exhausted"))?;
        if eof { return Ok(()); }
    }
}

async fn download_loop(
    mut writer: OwnedWriteHalf,
    endpoint: Endpoint,
    connect_timeout: Duration,
    session_id: String,
) -> io::Result<()> {
    let mut sequence = 0u64;
    loop {
        let response = request(&endpoint, connect_timeout, &session_id, "down", sequence, &[], false).await?;
        if !response.body.is_empty() {
            writer.write_all(&response.body).await?;
            writer.flush().await?;
        }
        sequence = sequence.checked_add(1).ok_or_else(|| io::Error::other("M5oH download sequence exhausted"))?;
        if response.headers.get("x-mst5-eof").is_some_and(|value| value == "1") {
            return writer.shutdown().await;
        }
    }
}

async fn request(
    endpoint: &Endpoint,
    connect_timeout: Duration,
    session_id: &str,
    channel: &str,
    sequence: u64,
    payload: &[u8],
    eof: bool,
) -> io::Result<HttpResponse> {
    let mut stream = connect(endpoint, connect_timeout).await?;
    let is_down = channel == "down";
    let method = if is_down {
        "GET"
    } else {
        match endpoint.route.as_deref() {
            Some("file-main") => "PUT",
            Some("call-main") => "PATCH",
            _ => "POST",
        }
    };
    let user_agent = endpoint
        .route
        .as_deref()
        .map(|route| format!("OVE-MST5-M5oH/{route}"))
        .unwrap_or_else(|| "OVE-MST5-M5oH/1".to_string());
    let target = endpoint
        .route
        .as_deref()
        .map(|route| format!("/m5/{route}"))
        .unwrap_or_else(|| "/".to_string());
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nX-MST5-Session: {session_id}\r\nX-MST5-Channel: {channel}\r\nX-MST5-Seq: {sequence}\r\nAccept: application/octet-stream\r\nUser-Agent: {user_agent}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        endpoint.host_header(),
    );
    if let Some(route) = &endpoint.route {
        head.push_str(&format!("X-MST5-Route: {route}\r\n"));
    }
    if is_down {
        head.push_str("X-MST5-Max-Response: 8388608\r\n");
    }
    if eof { head.push_str("X-MST5-EOF: 1\r\n"); }
    if !is_down {
        head.push_str(&format!("Content-Type: application/octet-stream\r\nContent-Length: {}\r\n", payload.len()));
    }
    head.push_str("\r\n");
    stream.get_mut().write_all(head.as_bytes()).await?;
    if !payload.is_empty() { stream.get_mut().write_all(payload).await?; }
    stream.get_mut().flush().await?;
    let response = read_response(&mut stream).await?;
    if response.status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("M5oH server returned HTTP {}: {}", response.status, String::from_utf8_lossy(&response.body)),
        ));
    }
    Ok(response)
}

async fn connect(endpoint: &Endpoint, connect_timeout: Duration) -> io::Result<BufReader<HttpStream>> {
    let address = if endpoint.host.contains(':') { format!("[{}]:{}", endpoint.host, endpoint.port) } else { format!("{}:{}", endpoint.host, endpoint.port) };
    let stream = timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "M5oH HTTP connect timed out"))??;
    stream.set_nodelay(true)?;
    if !endpoint.tls { return Ok(BufReader::new(HttpStream::Plain(stream))); }
    let roots = m5oh_roots()?;
    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = ServerName::try_from(endpoint.host.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid M5oH TLS hostname"))?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = timeout(connect_timeout, connector.connect(name, stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "M5oH TLS handshake timed out"))??;
    Ok(BufReader::new(HttpStream::Tls(stream)))
}

fn m5oh_roots() -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let production_ca = crate::decode_base64(OVE_PRODUCTION_CA_DER_B64)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("invalid embedded OVE M5oH CA: {error}")))?;
    roots.add(CertificateDer::from(production_ca))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("invalid embedded OVE M5oH CA: {error}")))?;
    Ok(roots)
}

async fn read_response(reader: &mut BufReader<HttpStream>) -> io::Result<HttpResponse> {
    let status_line = read_line(reader).await?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "M5oH HTTP peer closed"))?;
    let mut parts = status_line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "M5oH requires HTTP/1.1"));
    }
    let status = parts.next().unwrap_or_default().parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH HTTP status"))?;
    let mut headers = HashMap::new();
    let mut total = 0usize;
    loop {
        let line = read_line(reader).await?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "M5oH HTTP headers truncated"))?;
        total = total.checked_add(line.len()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "M5oH HTTP headers overflow"))?;
        if total > MAX_HTTP_HEAD { return Err(io::Error::new(io::ErrorKind::InvalidData, "M5oH HTTP headers too large")); }
        if line.is_empty() { break; }
        let (name, value) = line.split_once(':').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH HTTP header"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") { return Err(io::Error::new(io::ErrorKind::InvalidData, "chunked M5oH responses are unsupported")); }
    let length = headers.get("content-length").map(|value| value.parse::<usize>()).transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH content length"))?.unwrap_or(0);
    if length > MAX_HTTP_BODY { return Err(io::Error::new(io::ErrorKind::InvalidData, "M5oH response too large")); }
    let mut body = vec![0u8; length];
    if length != 0 { reader.read_exact(&mut body).await?; }
    Ok(HttpResponse { status, headers, body })
}

async fn read_line(reader: &mut BufReader<HttpStream>) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader.read_until(b'\n', &mut bytes).await?;
    if read == 0 { return Ok(None); }
    if bytes.len() > MAX_HTTP_HEAD || !bytes.ends_with(b"\r\n") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH HTTP line"));
    }
    bytes.truncate(bytes.len() - 2);
    String::from_utf8(bytes).map(Some).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "M5oH HTTP header is not UTF-8"))
}

fn random_session_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(format!("M5oH random session failed: {error}")))?;
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}
