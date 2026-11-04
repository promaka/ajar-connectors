// SPDX-License-Identifier: Apache-2.0
//! HTTP server transport: accept webhook deliveries; each request body is one
//! frame. HTTP/1.1, one path, `POST` or `PUT`, `Content-Length` or `chunked`,
//! every part of a request bounded before it is read. A saturated pipeline
//! answers `503`, so a well-behaved sender retries instead of losing the event.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::runtime::FrameSource;

/// A plain TCP connection, or the same connection after a TLS handshake.
trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

const MAX_FRAME: usize = crate::MAX_FRAME_BYTES;
/// Frames buffered across all connections before deliveries are refused.
const CHANNEL_FRAMES: usize = 256;
/// Total request-header bytes accepted before the request is refused.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Header lines accepted before the request is refused.
const MAX_HEADERS: usize = 64;
/// How long one request may take to arrive, against senders that dribble.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// `Retry-After` on a 503.
const RETRY_AFTER_SECS: u32 = 1;

#[derive(Clone)]
struct Settings {
    path: String,
    token: Option<String>,
}

/// How a delivery was answered. Only `Saturated` invites a retry of a valid
/// delivery.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Accepted,
    BadRequest,
    Unauthorized,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    NotImplemented,
    Saturated,
}

impl Outcome {
    fn status(self) -> (u16, &'static str) {
        match self {
            Outcome::Accepted => (204, "No Content"),
            Outcome::BadRequest => (400, "Bad Request"),
            Outcome::Unauthorized => (401, "Unauthorized"),
            Outcome::NotFound => (404, "Not Found"),
            Outcome::MethodNotAllowed => (405, "Method Not Allowed"),
            Outcome::PayloadTooLarge => (413, "Payload Too Large"),
            Outcome::NotImplemented => (501, "Not Implemented"),
            Outcome::Saturated => (503, "Service Unavailable"),
        }
    }
}

/// Frames delivered by webhook senders, in arrival order.
pub struct HttpServerSource {
    rx: mpsc::Receiver<Vec<u8>>,
    describe: String,
}

#[async_trait::async_trait]
impl FrameSource for HttpServerSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.rx.recv().await {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(n)
            }
            // The accept loop holds a sender for the source's lifetime.
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "http-server accept loop ended",
            )),
        }
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }
}

/// PEM paths for the listener's TLS. `client_ca` enables mutual TLS.
#[derive(Default)]
pub struct Tls<'a> {
    pub cert: Option<&'a str>,
    pub key: Option<&'a str>,
    pub client_ca: Option<&'a str>,
}

/// Bind now, so a bad `bind` or certificate fails at startup, and accept in
/// the background. A `token` without TLS refuses to start: the secret would be
/// on the wire in every delivery. So does half a certificate pair.
pub async fn open(
    bind: &str,
    path: &str,
    token: Option<String>,
    tls: Tls<'_>,
) -> anyhow::Result<HttpServerSource> {
    let acceptor = match (tls.cert, tls.key) {
        (Some(cert), Some(key)) => Some(tls_acceptor(cert, key, tls.client_ca)?),
        (None, None) => {
            if tls.client_ca.is_some() {
                anyhow::bail!(
                    "http-server: tls_client_ca needs tls_cert and tls_key; \
                     client certificates can only be verified over TLS"
                );
            }
            if token.is_some() {
                anyhow::bail!(
                    "http-server: token requires tls_cert and tls_key; a shared secret on a \
                     plaintext listener is sent in the clear with every delivery"
                );
            }
            tracing::warn!(bind = %bind, "http-server has no tls, data readable on the network");
            None
        }
        _ => anyhow::bail!("http-server: set both tls_cert and tls_key, or neither"),
    };

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding http-server {bind}"))?;
    let local = listener.local_addr()?;
    let settings = Settings {
        path: normalise_path(path),
        token,
    };
    let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
    let scheme = match (&acceptor, tls.client_ca) {
        (Some(_), Some(_)) => "https+mtls",
        (Some(_), None) => "https",
        (None, _) => "http",
    };
    let describe = format!("http-server {scheme}://{local}{}", settings.path);
    tokio::spawn(accept_loop(listener, settings, acceptor, tx));
    Ok(HttpServerSource { rx, describe })
}

/// The TLS acceptor; with `client_ca`, a client certificate chaining to it is
/// required.
fn tls_acceptor(cert: &str, key: &str, client_ca: Option<&str>) -> anyhow::Result<TlsAcceptor> {
    let chain = load_certs(cert)?;
    let key = load_key(key)?;
    let config = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in load_certs(ca)? {
                roots
                    .add(c)
                    .with_context(|| format!("adding client CA from {ca}"))?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .with_context(|| format!("building client verifier from {ca}"))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
        }
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key),
    }
    .context("building TLS server config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    PrivateKeyDer::from_pem_slice(&data).with_context(|| format!("parsing private key in {path}"))
}

/// One leading slash, no trailing one: `hook`, `/hook` and `/hook/` are equal.
fn normalise_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

async fn accept_loop(
    listener: TcpListener,
    settings: Settings,
    acceptor: Option<TlsAcceptor>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let (settings, tx) = (settings.clone(), tx.clone());
                match acceptor.clone() {
                    // The handshake runs on the connection task, so a stalled
                    // one never blocks the accept loop.
                    Some(acceptor) => {
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls) => connection_loop(tls, settings, tx, peer).await,
                                Err(e) => {
                                    tracing::debug!(peer = %peer, error = %e, "TLS handshake failed")
                                }
                            }
                        });
                    }
                    None => {
                        tokio::spawn(connection_loop(stream, settings, tx, peer));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Serve one connection until it closes, errors or goes idle. An outcome that
/// leaves a body unread closes it rather than guess where the next request
/// starts.
async fn connection_loop<S: Conn>(
    stream: S,
    settings: Settings,
    tx: mpsc::Sender<Vec<u8>>,
    peer: std::net::SocketAddr,
) {
    let mut reader = BufReader::new(stream);
    loop {
        // An empty fill is the peer's clean shutdown.
        match tokio::time::timeout(IDLE_TIMEOUT, reader.fill_buf()).await {
            Ok(Ok([])) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(_)) => {}
        }

        let (outcome, reusable) =
            match tokio::time::timeout(REQUEST_TIMEOUT, serve(&mut reader, &settings, &tx)).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::debug!(peer = %peer, "request timed out");
                    return;
                }
            };

        if outcome != Outcome::Accepted {
            let (code, _) = outcome.status();
            tracing::debug!(peer = %peer, status = code, "delivery refused");
        }
        if respond(reader.get_mut(), outcome, reusable).await.is_err() || !reusable {
            return;
        }
    }
}

/// Read one request and, if it is a valid delivery, queue its body as a frame.
/// Returns the outcome and whether the connection may carry another request.
async fn serve<S: Conn>(
    reader: &mut BufReader<S>,
    settings: &Settings,
    tx: &mpsc::Sender<Vec<u8>>,
) -> (Outcome, bool) {
    let head = match read_head(reader).await {
        Ok(head) => head,
        // The stream position is unknown after a bad head.
        Err(outcome) => return (outcome, false),
    };

    // Routing and authorisation come before any body is read.
    if head.path != settings.path {
        return (Outcome::NotFound, false);
    }
    if !head.method_allowed {
        return (Outcome::MethodNotAllowed, false);
    }
    if let Some(expected) = &settings.token {
        let presented = head.token.as_deref().unwrap_or("");
        if !secret_eq(expected.as_bytes(), presented.as_bytes()) {
            return (Outcome::Unauthorized, false);
        }
    }
    if let Some(len) = head.content_length {
        if len > MAX_FRAME {
            return (Outcome::PayloadTooLarge, false);
        }
    }
    if head.content_length.is_none() && !head.chunked {
        // No body: a health probe, not an event.
        return (Outcome::Accepted, true);
    }

    // `Expect: 100-continue` senders wait for this line before the body.
    if head.expect_continue
        && reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .is_err()
    {
        return (Outcome::BadRequest, false);
    }

    let body = match read_body(reader, &head).await {
        Ok(body) => body,
        Err(outcome) => return (outcome, false),
    };

    match tx.try_send(body) {
        Ok(()) => (Outcome::Accepted, true),
        Err(mpsc::error::TrySendError::Full(_)) => (Outcome::Saturated, true),
        // The connector is shutting down.
        Err(mpsc::error::TrySendError::Closed(_)) => (Outcome::Saturated, false),
    }
}

struct Head {
    method_allowed: bool,
    path: String,
    content_length: Option<usize>,
    chunked: bool,
    expect_continue: bool,
    token: Option<String>,
}

/// Read the request line and headers, bounded in both count and bytes.
async fn read_head<S: Conn>(reader: &mut BufReader<S>) -> Result<Head, Outcome> {
    let mut budget = MAX_HEADER_BYTES;
    let request_line = read_line(reader, &mut budget).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() {
        return Err(Outcome::BadRequest);
    }

    let mut head = Head {
        method_allowed: method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT"),
        path: normalise_path(target.split(['?', '#']).next().unwrap_or("/")),
        content_length: None,
        chunked: false,
        expect_continue: false,
        token: None,
    };

    for _ in 0..MAX_HEADERS {
        let line = read_line(reader, &mut budget).await?;
        if line.is_empty() {
            return Ok(head);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Outcome::BadRequest);
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            head.content_length = Some(value.parse().map_err(|_| Outcome::BadRequest)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if value.eq_ignore_ascii_case("chunked") {
                head.chunked = true;
            } else {
                return Err(Outcome::NotImplemented);
            }
        } else if name.eq_ignore_ascii_case("expect") {
            head.expect_continue = value.eq_ignore_ascii_case("100-continue");
        } else if name.eq_ignore_ascii_case("x-ajar-token") {
            head.token = Some(value.to_string());
        }
    }
    Err(Outcome::BadRequest)
}

/// Read one CRLF-terminated header line, charging it against the head budget.
async fn read_line<S: Conn>(
    reader: &mut BufReader<S>,
    budget: &mut usize,
) -> Result<String, Outcome> {
    let mut raw = Vec::new();
    let n = reader
        .read_until(b'\n', &mut raw)
        .await
        .map_err(|_| Outcome::BadRequest)?;
    // The connection ended mid-head.
    if n == 0 {
        return Err(Outcome::BadRequest);
    }
    *budget = budget.checked_sub(n).ok_or(Outcome::BadRequest)?;
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
    String::from_utf8(raw).map_err(|_| Outcome::BadRequest)
}

/// Read the body described by `head`, never allocating past [`MAX_FRAME`].
async fn read_body<S: Conn>(reader: &mut BufReader<S>, head: &Head) -> Result<Vec<u8>, Outcome> {
    if head.chunked {
        return read_chunked(reader).await;
    }
    let len = head.content_length.unwrap_or(0);
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| Outcome::BadRequest)?;
    Ok(body)
}

/// Read a chunked body, checking the running total against [`MAX_FRAME`] on
/// every chunk.
async fn read_chunked<S: Conn>(reader: &mut BufReader<S>) -> Result<Vec<u8>, Outcome> {
    let mut body = Vec::new();
    loop {
        let mut budget = MAX_HEADER_BYTES;
        let line = read_line(reader, &mut budget).await?;
        // A chunk size may carry extensions after a semicolon.
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| Outcome::BadRequest)?;
        if size == 0 {
            // Trailers, then the terminating blank line.
            let mut budget = MAX_HEADER_BYTES;
            while !read_line(reader, &mut budget).await?.is_empty() {}
            return Ok(body);
        }
        if body.len().saturating_add(size) > MAX_FRAME {
            return Err(Outcome::PayloadTooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .await
            .map_err(|_| Outcome::BadRequest)?;
        // Each chunk is followed by CRLF.
        let mut budget = MAX_HEADER_BYTES;
        read_line(reader, &mut budget).await?;
    }
}

/// Write the response, always with `Content-Length: 0` and `Connection`.
async fn respond<S: Conn>(stream: &mut S, outcome: Outcome, reusable: bool) -> std::io::Result<()> {
    let (code, reason) = outcome.status();
    let connection = if reusable { "keep-alive" } else { "close" };
    let mut response =
        format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: {connection}\r\n");
    if outcome == Outcome::Saturated {
        response.push_str(&format!("Retry-After: {RETRY_AFTER_SECS}\r\n"));
    }
    if outcome == Outcome::MethodNotAllowed {
        response.push_str("Allow: POST, PUT\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// Constant-time equality, so a token cannot be recovered by timing. The length
/// leaks.
fn secret_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// The bound address, read back from the description.
    fn addr(src: &HttpServerSource, scheme: &str) -> String {
        src.describe()
            .strip_prefix(&format!("http-server {scheme}://"))
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string()
    }

    /// A plaintext source on an ephemeral port, with its address.
    async fn server(path: &str, token: Option<String>) -> (HttpServerSource, String) {
        let src = open("127.0.0.1:0", path, token, Tls::default())
            .await
            .unwrap();
        let addr = addr(&src, "http");
        (src, addr)
    }

    async fn open_error(token: Option<String>, tls: Tls<'_>) -> String {
        open("127.0.0.1:0", "/", token, tls)
            .await
            .err()
            .unwrap()
            .to_string()
    }

    /// Send raw bytes on a fresh connection and read whatever comes back.
    async fn send(addr: &str, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(raw.as_bytes()).await.unwrap();
        let mut out = vec![0u8; 512];
        let n = c.read(&mut out).await.unwrap();
        String::from_utf8_lossy(&out[..n]).into_owned()
    }

    fn post(path: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn delivers_a_posted_body_as_one_frame() {
        let (mut src, addr) = server("/", None).await;
        let reply = send(&addr, &post("/", r#"{"lat":1.5}"#)).await;
        assert!(reply.starts_with("HTTP/1.1 204"), "{reply}");

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], br#"{"lat":1.5}"#);
    }

    #[tokio::test]
    async fn reads_a_chunked_body_with_extensions() {
        let (mut src, addr) = server("/", None).await;
        let raw = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                   3;meta=1\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n";
        let reply = send(&addr, raw).await;
        assert!(reply.starts_with("HTTP/1.1 204"), "{reply}");

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn answers_expect_100_continue_before_the_body() {
        let (mut src, addr) = server("/", None).await;
        let mut c = TcpStream::connect(&addr).await.unwrap();
        c.write_all(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n",
        )
        .await
        .unwrap();

        let mut out = vec![0u8; 128];
        let n = c.read(&mut out).await.unwrap();
        assert!(
            String::from_utf8_lossy(&out[..n]).starts_with("HTTP/1.1 100"),
            "expected an interim 100 before sending the body"
        );

        c.write_all(b"hi").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
    }

    #[tokio::test]
    async fn keeps_the_connection_alive_across_deliveries() {
        let (mut src, addr) = server("/", None).await;
        let mut c = TcpStream::connect(&addr).await.unwrap();
        for expected in ["one", "two", "three"] {
            c.write_all(post("/", expected).as_bytes()).await.unwrap();
            let mut out = vec![0u8; 256];
            let n = c.read(&mut out).await.unwrap();
            assert!(String::from_utf8_lossy(&out[..n]).contains("204"));
            let mut buf = vec![0u8; 64];
            let n = src.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn refuses_an_oversized_body_without_reading_it() {
        let (_src, addr) = server("/", None).await;
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_FRAME + 1
        );
        assert!(send(&addr, &raw).await.starts_with("HTTP/1.1 413"));
    }

    #[tokio::test]
    async fn refuses_an_oversized_chunked_body() {
        let (_src, addr) = server("/", None).await;
        let big = "a".repeat(4096);
        let mut raw =
            String::from("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        // Past MAX_FRAME in aggregate, no single chunk large.
        for _ in 0..20 {
            raw.push_str(&format!("1000\r\n{big}\r\n"));
        }
        assert!(send(&addr, &raw).await.starts_with("HTTP/1.1 413"));
    }

    #[tokio::test]
    async fn enforces_path_and_method() {
        let (_src, addr) = server("/hook", None).await;

        let wrong_path = "POST /nope HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx";
        assert!(send(&addr, wrong_path).await.starts_with("HTTP/1.1 404"));

        let wrong_method = "GET /hook HTTP/1.1\r\nHost: x\r\n\r\n".to_string();
        let reply = send(&addr, &wrong_method).await;
        assert!(reply.starts_with("HTTP/1.1 405"), "{reply}");
        assert!(reply.contains("Allow: POST, PUT"));

        let ok = "POST /hook/?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx";
        assert!(
            send(&addr, ok).await.starts_with("HTTP/1.1 204"),
            "query string and trailing slash still route"
        );
    }

    #[tokio::test]
    async fn refuses_rather_than_sheds_when_saturated() {
        let (_src, addr) = server("/", None).await;
        let mut refused = false;
        for _ in 0..(CHANNEL_FRAMES + 8) {
            if send(&addr, &post("/", "x"))
                .await
                .starts_with("HTTP/1.1 503")
            {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "a saturated pipeline must refuse the delivery so the sender retries"
        );
    }

    #[tokio::test]
    async fn rejects_malformed_and_unsupported_requests() {
        let (_src, addr) = server("/", None).await;
        assert!(send(&addr, "not-http\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(send(&addr, "POST / HTTP/1.1\r\nbroken-header\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 400"));
        let gzip = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(send(&addr, gzip).await.starts_with("HTTP/1.1 501"));
    }

    #[test]
    fn paths_normalise_to_one_form() {
        assert_eq!(normalise_path("hook"), "/hook");
        assert_eq!(normalise_path("/hook"), "/hook");
        assert_eq!(normalise_path("/hook/"), "/hook");
        assert_eq!(normalise_path(""), "/");
        assert_eq!(normalise_path("/"), "/");
    }

    #[test]
    fn secret_comparison_is_length_and_content_sensitive() {
        assert!(secret_eq(b"abc", b"abc"));
        assert!(!secret_eq(b"abc", b"abd"));
        assert!(!secret_eq(b"abc", b"ab"));
        assert!(secret_eq(b"", b""));
    }

    /// A self-signed cert and key for `localhost` in `dir`: their paths and the
    /// certificate DER, so a test client can trust exactly it.
    fn self_signed(dir: &tempfile::TempDir) -> (String, String, CertificateDer<'static>) {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, issued.cert.pem()).unwrap();
        std::fs::write(&key_path, issued.signing_key.serialize_pem()).unwrap();
        let der = CertificateDer::from(issued.cert.der().to_vec());
        (
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
            der,
        )
    }

    #[tokio::test]
    async fn serves_a_delivery_over_tls() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key, der) = self_signed(&dir);
        let mut src = open(
            "127.0.0.1:0",
            "/",
            Some("s3cret".into()),
            Tls {
                cert: Some(&cert),
                key: Some(&key),
                ..Tls::default()
            },
        )
        .await
        .unwrap();
        let addr = addr(&src, "https");

        let mut roots = RootCertStore::empty();
        roots.add(der).unwrap();
        let client = tokio_rustls::TlsConnector::from(Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = client.connect(name, tcp).await.unwrap();

        let body = r#"{"detected":true}"#;
        let req = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nX-Ajar-Token: s3cret\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut out = vec![0u8; 256];
        let n = tls.read(&mut out).await.unwrap();
        assert!(
            String::from_utf8_lossy(&out[..n]).starts_with("HTTP/1.1 204"),
            "delivery over TLS should be accepted"
        );

        let mut buf = vec![0u8; 256];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], body.as_bytes());

        for headers in ["X-Ajar-Token: wrong\r\n", ""] {
            let tcp = TcpStream::connect(&addr).await.unwrap();
            let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = client.connect(name, tcp).await.unwrap();
            let req = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: 1\r\n\r\nx"
            );
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut out = vec![0u8; 128];
            let n = tls.read(&mut out).await.unwrap();
            assert!(
                String::from_utf8_lossy(&out[..n]).starts_with("HTTP/1.1 401"),
                "a wrong or absent token is refused: {headers:?}"
            );
        }
    }

    #[tokio::test]
    async fn token_without_tls_refuses_to_start() {
        let err = open_error(Some("s3cret".into()), Tls::default()).await;
        assert!(err.contains("token requires tls_cert and tls_key"), "{err}");
    }

    #[tokio::test]
    async fn half_a_certificate_pair_refuses_to_start() {
        let tls = Tls {
            cert: Some("/nonexistent.crt"),
            ..Tls::default()
        };
        let err = open_error(None, tls).await;
        assert!(err.contains("both tls_cert and tls_key"), "{err}");
    }

    #[tokio::test]
    async fn client_certificates_need_tls() {
        let tls = Tls {
            client_ca: Some("/some/ca.crt"),
            ..Tls::default()
        };
        let err = open_error(None, tls).await;
        assert!(err.contains("tls_client_ca needs tls_cert"), "{err}");
    }
}
