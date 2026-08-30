//! MST5 over HTTP(S) client transport.
//!
//! The protocol purposely uses two independent HTTP/1.1 streams.  `up` carries
//! bytes written by MST5, and long-polled `down` responses carry bytes received
//! from MST5.  A short-lived loopback TCP connection lets the rest of the
//! client keep the same audited Noise and frame implementation as raw MST5.

#[cfg(feature = "m5oh-tls")]
use rustls::pki_types::{CertificateDer, ServerName};
#[cfg(feature = "m5oh-tls")]
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV4;
use std::pin::Pin;
#[cfg(feature = "m5oh-tls")]
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream,
};
use tokio::time::timeout;
#[cfg(feature = "m5oh-tls")]
use tokio_rustls::{client::TlsStream, TlsConnector};

const MAX_HTTP_HEAD: usize = 64 * 1024;
const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;
// The CDN budget is 23 KiB per GET payload. Packet-routed M5oH reserves the
// first eight bytes for the opaque node port carried inside `r`.
const UPLOAD_CHUNK: usize = 23 * 1024 - 8;
const UPLOAD_COALESCE: Duration = Duration::from_millis(2);
const PACKET_ROUTE_DESTINATION_BYTES: usize = 8;
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
    /// New packet-routed M5oH. `None` retains legacy selectors or triggers
    /// a node-directory lookup for a bare M5oH endpoint.
    pub(crate) packet_destination: Option<SocketAddrV4>,
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
    #[cfg(feature = "m5oh-tls")]
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "m5oh-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "m5oh-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "m5oh-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "m5oh-tls")]
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

pub(crate) async fn open_loopback_bridge(
    endpoint: Endpoint,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    let endpoint = discover_default_node(endpoint, connect_timeout).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let _ = bridge(stream, endpoint, connect_timeout).await;
    });
    timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "M5oH local bridge timed out"))?
}

#[derive(serde::Deserialize)]
struct NodeDirectory {
    version: u8,
    nodes: Vec<NodeDirectoryEntry>,
}

#[derive(serde::Deserialize)]
struct NodeDirectoryEntry {
    id: String,
    destination: String,
    default: bool,
}

async fn discover_default_node(
    mut endpoint: Endpoint,
    connect_timeout: Duration,
) -> io::Result<Endpoint> {
    if endpoint.packet_destination.is_some() || endpoint.route.is_some() {
        return Ok(endpoint);
    }
    let mut stream = connect(&endpoint, connect_timeout).await?;
    let head = format!(
		"GET / HTTP/1.1\r\nHost: {}\r\nAccept: application/vnd.mst5.nodes+json\r\nUser-Agent: OVE-MST5-M5oH/1\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		endpoint.host_header(),
	);
    stream.get_mut().write_all(head.as_bytes()).await?;
    stream.get_mut().flush().await?;
    let response = read_response(&mut stream).await?;
    if response.status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("M5oH node directory returned HTTP {}", response.status),
        ));
    }
    let directory: NodeDirectory = serde_json::from_slice(&response.body).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "M5oH node directory is invalid")
    })?;
    if directory.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported M5oH node directory version",
        ));
    }
    let node = directory
        .nodes
        .into_iter()
        .find(|node| node.default)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "M5oH node directory has no default node",
            )
        })?;
    let destination = node.destination.parse::<SocketAddrV4>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid M5oH node destination for {}", node.id),
        )
    })?;
    if destination.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "M5oH node directory has zero port",
        ));
    }
    endpoint.packet_destination = Some(destination);
    Ok(endpoint)
}

async fn bridge(
    stream: TcpStream,
    endpoint: Endpoint,
    connect_timeout: Duration,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let session_id = random_session_id()?;
    // seq=0 creates the remote TCP connection before the local client writes
    // the Noise prologue. This avoids a race with its initial read.
    request(&endpoint, connect_timeout, &session_id, "up", 0, &[], false).await?;
    let (reader, writer) = stream.into_split();
    let mut upload = tokio::spawn(upload_loop(
        reader,
        endpoint.clone(),
        connect_timeout,
        session_id.clone(),
    ));
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
    let mut http = connect(&endpoint, connect_timeout).await?;
    loop {
        let mut count = reader.read(&mut buffer).await?;
        let mut eof = count == 0;
        // Coalesce immediately available MST5 records, but cap the added
        // interactive latency at two milliseconds and never exceed CDN GET.
        while !eof && count < buffer.len() {
            match timeout(UPLOAD_COALESCE, reader.read(&mut buffer[count..])).await {
                Ok(Ok(0)) => {
                    eof = true;
                    break;
                }
                Ok(Ok(read)) => count += read,
                Ok(Err(error)) => return Err(error),
                Err(_) => break,
            }
        }
        let response = match request_on(
            &mut http,
            &endpoint,
            &session_id,
            "up",
            sequence,
            &buffer[..count],
            eof,
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                http = connect(&endpoint, connect_timeout).await?;
                request_on(
                    &mut http,
                    &endpoint,
                    &session_id,
                    "up",
                    sequence,
                    &buffer[..count],
                    eof,
                )
                .await?
            }
        };
        if response
            .headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            http = connect(&endpoint, connect_timeout).await?;
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("M5oH upload sequence exhausted"))?;
        if eof {
            return Ok(());
        }
    }
}

async fn download_loop(
    mut writer: OwnedWriteHalf,
    endpoint: Endpoint,
    connect_timeout: Duration,
    session_id: String,
) -> io::Result<()> {
    let mut sequence = 0u64;
    let mut http = connect(&endpoint, connect_timeout).await?;
    loop {
        let response = match request_on(
            &mut http,
            &endpoint,
            &session_id,
            "down",
            sequence,
            &[],
            false,
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                http = connect(&endpoint, connect_timeout).await?;
                request_on(
                    &mut http,
                    &endpoint,
                    &session_id,
                    "down",
                    sequence,
                    &[],
                    false,
                )
                .await?
            }
        };
        if !response.body.is_empty() {
            writer.write_all(&response.body).await?;
            writer.flush().await?;
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("M5oH download sequence exhausted"))?;
        if response
            .headers
            .get("x-mst5-eof")
            .is_some_and(|value| value == "1")
        {
            return writer.shutdown().await;
        }
        if response
            .headers
            .get("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            http = connect(&endpoint, connect_timeout).await?;
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
    request_on(
        &mut stream,
        endpoint,
        session_id,
        channel,
        sequence,
        payload,
        eof,
    )
    .await
}

async fn request_on(
    stream: &mut BufReader<HttpStream>,
    endpoint: &Endpoint,
    session_id: &str,
    channel: &str,
    sequence: u64,
    payload: &[u8],
    eof: bool,
) -> io::Result<HttpResponse> {
    let is_down = channel == "down";
    let method = "GET";
    // The packet-routed form is intentionally ordinary `/?r=...`: the node
    // destination selector is prepended to the Base64URL payload, never
    // exposed in a URL or header.
    let user_agent = "OVE-MST5-M5oH/1";
    let target = get_target(
        endpoint.route.as_deref(),
        endpoint.packet_destination,
        payload,
    );
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nX-MST5-Session: {session_id}\r\nX-MST5-Channel: {channel}\r\nX-MST5-Seq: {sequence}\r\nAccept: application/octet-stream\r\nUser-Agent: {user_agent}\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n",
        endpoint.host_header(),
    );
    if is_down {
        head.push_str("X-MST5-Max-Response: 8388608\r\n");
    }
    if eof {
        head.push_str("X-MST5-EOF: 1\r\n");
    }
    head.push_str("\r\n");
    stream.get_mut().write_all(head.as_bytes()).await?;
    stream.get_mut().flush().await?;
    let response = read_response(&mut *stream).await?;
    if response.status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!(
                "M5oH server returned HTTP {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            ),
        ));
    }
    Ok(response)
}

/// Bit.Proxy-compatible GET framing.  Keep the route before the payload so a
/// shared router can choose the upstream without relying on HTTP methods.
fn get_target(
    _route: Option<&str>,
    packet_destination: Option<SocketAddrV4>,
    payload: &[u8],
) -> String {
    if let Some(destination) = packet_destination {
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.extend_from_slice(&packet_route_permute(destination));
        packet.extend_from_slice(payload);
        return format!("/?r={}", base64url_no_pad(&packet));
    }
    let encoded = base64url_no_pad(payload);
    if payload.is_empty() {
        "/".to_string()
    } else {
        format!("/?r={encoded}")
    }
}

fn packet_route_permute(destination: SocketAddrV4) -> [u8; PACKET_ROUTE_DESTINATION_BYTES] {
    let mut logical = [0u8; PACKET_ROUTE_DESTINATION_BYTES];
    logical[..2].copy_from_slice(&destination.port().to_be_bytes());
    logical[2..6].copy_from_slice(&destination.ip().octets());
    // wire = logical[1,8,4,6,2,7,5,3]
    [
        logical[0], logical[7], logical[3], logical[5], logical[1], logical[6], logical[4],
        logical[2],
    ]
}

fn base64url_no_pad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[((first & 0x03) << 4 | second >> 4) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((second & 0x0f) << 2 | third >> 6) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::get_target;

    #[test]
    fn human_readable_route_selector_is_not_emitted() {
        assert_eq!(get_target(Some("main"), None, &[]), "/");
        assert_eq!(get_target(Some("file-main"), None, &[0, 1, 2]), "/?r=AAEC");
        assert_eq!(get_target(None, None, &[0, 1]), "/?r=AAE");
    }

    #[test]
    fn packet_destination_is_inside_the_get_payload_in_permuted_order() {
        let destination = "10.100.2.228:8080".parse().unwrap();
        let target = get_target(None, Some(destination), &[0, 1]);
        assert_eq!(target, "/?r=HwBk5JAAAgoAAQ");
        assert!(!target.contains("m5="));
    }

    #[test]
    fn routed_get_target_fits_the_cdn_limit() {
        let destination = "10.100.2.228:8081".parse().unwrap();
        let target = get_target(None, Some(destination), &vec![0x5a; super::UPLOAD_CHUNK]);
        assert_eq!(target.len(), 31_407);
    }
}

async fn connect(
    endpoint: &Endpoint,
    connect_timeout: Duration,
) -> io::Result<BufReader<HttpStream>> {
    let address = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let stream = timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "M5oH HTTP connect timed out"))??;
    stream.set_nodelay(true)?;
    if !endpoint.tls {
        return Ok(BufReader::new(HttpStream::Plain(stream)));
    }
    #[cfg(feature = "m5oh-tls")]
    {
        let roots = m5oh_roots()?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid M5oH TLS hostname")
        })?;
        let connector = TlsConnector::from(Arc::new(config));
        let stream = timeout(connect_timeout, connector.connect(name, stream))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "M5oH TLS handshake timed out")
            })??;
        return Ok(BufReader::new(HttpStream::Tls(stream)));
    }
    #[cfg(not(feature = "m5oh-tls"))]
    {
        let _ = stream;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "M5oH HTTPS is unavailable in this build",
        ))
    }
}

#[cfg(feature = "m5oh-tls")]
fn m5oh_roots() -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let production_ca = crate::decode_base64(OVE_PRODUCTION_CA_DER_B64).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid embedded OVE M5oH CA: {error}"),
        )
    })?;
    roots
        .add(CertificateDer::from(production_ca))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid embedded OVE M5oH CA: {error}"),
            )
        })?;
    Ok(roots)
}

async fn read_response(reader: &mut BufReader<HttpStream>) -> io::Result<HttpResponse> {
    let status_line = read_line(reader)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "M5oH HTTP peer closed"))?;
    let mut parts = status_line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "M5oH requires HTTP/1.1",
        ));
    }
    let status = parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH HTTP status"))?;
    let mut headers = HashMap::new();
    let mut total = 0usize;
    loop {
        let line = read_line(reader).await?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "M5oH HTTP headers truncated")
        })?;
        total = total.checked_add(line.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "M5oH HTTP headers overflow")
        })?;
        if total > MAX_HTTP_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "M5oH HTTP headers too large",
            ));
        }
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH HTTP header")
        })?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked M5oH responses are unsupported",
        ));
    }
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid M5oH content length"))?
        .unwrap_or(0);
    if length > MAX_HTTP_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "M5oH response too large",
        ));
    }
    let mut body = vec![0u8; length];
    if length != 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

async fn read_line(reader: &mut BufReader<HttpStream>) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let read = reader.read_until(b'\n', &mut bytes).await?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_HTTP_HEAD || !bytes.ends_with(b"\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid M5oH HTTP line",
        ));
    }
    bytes.truncate(bytes.len() - 2);
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "M5oH HTTP header is not UTF-8"))
}

fn random_session_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("M5oH random session failed: {error}")))?;
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}
