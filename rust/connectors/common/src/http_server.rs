// SPDX-License-Identifier: Apache-2.0
//! HTTP server transport — accept webhook deliveries from sources that can only
//! POST to a URL: IP cameras and VMS event notifications, SDR republishers, SaaS
//! callbacks. Each request body is one frame.
//!
//! This is the only transport that can answer the sender. The datagram and stream
//! transports take whatever arrives and shed it if the pipeline is saturated,
//! because there is nobody to tell. A webhook client reads the status code, so
//! refusing a delivery with `503` makes a well-behaved sender retry instead of
//! losing the event: delivery is as durable as the sender's retry policy, which is
//! stronger than anything else in the suite.
//!
//! The parser is deliberately small. HTTP/1.1, one configured path, `POST` or
//! `PUT`, `Content-Length` or `chunked` bodies. Every dimension of a request is
//! bounded before it is read (header count, header bytes, body bytes) so neither a
//! hostile nor a merely broken client can grow memory, and a connection that stops
//! making progress is closed on a timeout rather than held open.

use rustls_pki_types::pem::PemObject;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use crate::runtime::FrameSource;

/// A stream this transport can serve a request over: a plain TCP connection, or
/// the same connection after a TLS handshake.
trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

/// Matches the runtime's receive buffer: one frame can never exceed it.
const MAX_FRAME: usize = 64 * 1024;
/// Frames buffered across all connections before deliveries are refused with 503.
const CHANNEL_FRAMES: usize = 256;
/// Total request-header bytes accepted before the request is refused.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Header lines accepted before the request is refused.
const MAX_HEADERS: usize = 64;
/// How long one request may take to arrive once a connection is active. Bounds
/// slow-loris: a sender that dribbles headers is closed rather than held.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an idle keep-alive connection is held open between deliveries.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Seconds a refused sender is asked to wait before retrying.
const RETRY_AFTER_SECS: u32 = 1;

/// Settings shared by every connection on one listener.
#[derive(Clone)]
struct Settings {
    /// Path a delivery must target; anything else is 404.
    path: String,
    /// Shared secret required in `X-Ajar-Token`, if the operator set one.
    token: Option<String>,
}

/// How a delivery was answered. The status is what the sender sees, and it is the
/// contract with their retry logic: only `Saturated` invites a retry of an
/// otherwise-valid delivery.
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
    /// The status line sent for this outcome.
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
            // The accept loop holds a sender for the lifetime of the source, so
            // this only happens if it died — surface it rather than spin.
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

/// How the listener protects the hop from the sender.
pub struct Tls<'a> {
    /// PEM certificate chain served to senders.
    pub cert: Option<&'a str>,
    /// PEM private key for `cert`.
    pub key: Option<&'a str>,
    /// PEM CA bundle client certificates must chain to; enables mutual TLS.
    pub client_ca: Option<&'a str>,
}

/// Bind and start accepting deliveries. Binding is eager (a bad `bind` or an
/// unreadable certificate fails fast at startup); connections are handled in the
/// background.
///
/// TLS is fail-closed in the same way the NATS connection is. A `token` on a
/// plaintext listener refuses to start, because the secret would be on the wire in
/// every delivery and a sender that captured it could inject events the connector
/// would then sign. A partially configured certificate pair is a slip, not a
/// preference, so it refuses too.
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
                    "http-server: tls_client_ca needs tls_cert and tls_key — \
                     client certificates can only be verified over TLS"
                );
            }
            if token.is_some() {
                anyhow::bail!(
                    "http-server: token requires tls_cert and tls_key — a shared secret on a \
                     plaintext listener is sent in the clear with every delivery"
                );
            }
            tracing::warn!(
                "http-server is serving plaintext: deliveries and their contents are \
                 readable on the wire (use only on a physically protected segment)"
            );
            None
        }
        _ => anyhow::bail!("http-server: set both tls_cert and tls_key, or neither"),
    };

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("binding http-server {bind}: {e}"))?;
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

/// Build the TLS acceptor. With `client_ca` set the listener requires a client
/// certificate chaining to it, which authenticates the sender by key rather than
/// by a bearer token and is the stronger option wherever the sender supports it.
fn tls_acceptor(cert: &str, key: &str, client_ca: Option<&str>) -> anyhow::Result<TlsAcceptor> {
    let chain = load_certs(cert)?;
    let key = load_key(key)?;
    let config = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in load_certs(ca)? {
                roots
                    .add(c)
                    .map_err(|e| anyhow::anyhow!("adding client CA from {ca}: {e}"))?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| anyhow::anyhow!("building client verifier from {ca}: {e}"))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain, key)
        }
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key),
    }
    .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(&data).collect();
    let certs = certs.map_err(|e| anyhow::anyhow!("parsing certificates in {path}: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    PrivateKeyDer::from_pem_slice(&data)
        .map_err(|e| anyhow::anyhow!("parsing private key in {path}: {e}"))
}

/// A configured path always compares with a single leading slash and no trailing
/// one, so `hook`, `/hook` and `/hook/` are the same endpoint.
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
                    // The handshake runs on the connection task, so a stalled or
                    // hostile handshake never blocks the accept loop.
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

/// Serve one connection until it closes, errors, or goes idle. Keep-alive is
/// honoured only while the stream stays in sync: any outcome that leaves an
/// unread body closes the connection instead of guessing where the next request
/// starts.
async fn connection_loop<S: Transport>(
    stream: S,
    settings: Settings,
    tx: mpsc::Sender<Vec<u8>>,
    peer: std::net::SocketAddr,
) {
    let mut reader = BufReader::new(stream);
    loop {
        // Wait for the next request, closing an idle keep-alive connection rather
        // than holding it open. An empty fill is the peer's clean shutdown.
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
async fn serve<S: Transport>(
    reader: &mut BufReader<S>,
    settings: &Settings,
    tx: &mpsc::Sender<Vec<u8>>,
) -> (Outcome, bool) {
    let head = match read_head(reader).await {
        Ok(head) => head,
        // Malformed or over-long head: the stream position is unknown, so close.
        Err(outcome) => return (outcome, false),
    };

    // Routing and authorisation are cheap and are checked before any body is read,
    // so a misdirected or unauthorised sender never gets to spend our memory.
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
            // Refuse before reading: the body never enters memory.
            return (Outcome::PayloadTooLarge, false);
        }
    }
    if head.content_length.is_none() && !head.chunked {
        // A delivery with no body is not an event. Treat it as a health probe.
        return (Outcome::Accepted, true);
    }

    // `Expect: 100-continue` senders (curl, some VMS clients) wait for this line
    // before sending the body; without it they stall for a fixed timeout.
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

    // Backpressure is the point of this transport: rather than shedding silently,
    // refuse the delivery so the sender retries it.
    match tx.try_send(body) {
        Ok(()) => (Outcome::Accepted, true),
        Err(mpsc::error::TrySendError::Full(_)) => (Outcome::Saturated, true),
        // Source dropped; the connector is shutting down.
        Err(mpsc::error::TrySendError::Closed(_)) => (Outcome::Saturated, false),
    }
}

/// The parts of a request head this transport acts on.
struct Head {
    method_allowed: bool,
    path: String,
    content_length: Option<usize>,
    chunked: bool,
    expect_continue: bool,
    token: Option<String>,
}

/// Read the request line and headers, bounded in both count and bytes.
async fn read_head<S: Transport>(reader: &mut BufReader<S>) -> Result<Head, Outcome> {
    let mut budget = MAX_HEADER_BYTES;
    let request_line = read_line(reader, &mut budget).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(Outcome::BadRequest);
    }

    let mut head = Head {
        // A webhook is a write. Anything else is a client pointed at the wrong
        // place, and is told so rather than silently accepted.
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
            // Only chunked is defined for requests we accept; anything else
            // (compressed transfer codings) is refused rather than mis-read.
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
    // More header lines than the bound allows.
    Err(Outcome::BadRequest)
}

/// Read one CRLF-terminated header line, charging it against the head budget.
async fn read_line<S: Transport>(
    reader: &mut BufReader<S>,
    budget: &mut usize,
) -> Result<String, Outcome> {
    let mut raw = Vec::new();
    let n = reader
        .read_until(b'\n', &mut raw)
        .await
        .map_err(|_| Outcome::BadRequest)?;
    if n == 0 {
        return Err(Outcome::BadRequest); // connection ended mid-head
    }
    *budget = budget.checked_sub(n).ok_or(Outcome::BadRequest)?;
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
    String::from_utf8(raw).map_err(|_| Outcome::BadRequest)
}

/// Read the body described by `head`, never allocating past [`MAX_FRAME`].
async fn read_body<S: Transport>(
    reader: &mut BufReader<S>,
    head: &Head,
) -> Result<Vec<u8>, Outcome> {
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

/// Read a `Transfer-Encoding: chunked` body. The running total is checked against
/// [`MAX_FRAME`] on every chunk, so a sender cannot exceed the bound by splitting.
async fn read_chunked<S: Transport>(reader: &mut BufReader<S>) -> Result<Vec<u8>, Outcome> {
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

/// Write the response. Every response carries an explicit `Content-Length: 0` and
/// an explicit `Connection`, so a sender never has to guess where it ends.
async fn respond<S: Transport>(
    stream: &mut S,
    outcome: Outcome,
    reusable: bool,
) -> std::io::Result<()> {
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

/// Constant-time equality, so a token cannot be recovered by timing responses.
/// The length is allowed to leak, which is standard for a fixed-format secret.
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

    /// Open a source on an ephemeral port and return it with its address.
    async fn server(path: &str, token: Option<String>) -> (HttpServerSource, String) {
        let src = open(
            "127.0.0.1:0",
            path,
            token,
            Tls {
                cert: None,
                key: None,
                client_ca: None,
            },
        )
        .await
        .unwrap();
        let addr = src
            .describe()
            .strip_prefix("http-server http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();
        (src, addr)
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
    async fn reads_a_chunked_body() {
        let (mut src, addr) = server("/", None).await;
        // "hello" split across two chunks, with an extension on the first.
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
        // Well past MAX_FRAME in aggregate, but no single chunk is large.
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

        // A query string still routes, and the trailing slash is the same endpoint.
        let ok = "POST /hook/?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx";
        assert!(send(&addr, ok).await.starts_with("HTTP/1.1 204"));
    }

    #[tokio::test]
    async fn refuses_rather_than_sheds_when_saturated() {
        // Never read from the source, so the channel fills and stays full.
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

    /// Write a throwaway self-signed cert/key pair for `localhost` and return the
    /// paths plus the certificate DER, so a test client can trust exactly it.
    fn self_signed() -> (String, String, CertificateDer<'static>) {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir();
        let stem = format!(
            "ajar-http-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let cert_path = dir.join(format!("{stem}.crt"));
        let key_path = dir.join(format!("{stem}.key"));
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
        let (cert, key, der) = self_signed();
        let mut src = open(
            "127.0.0.1:0",
            "/",
            Some("s3cret".into()),
            Tls {
                cert: Some(&cert),
                key: Some(&key),
                client_ca: None,
            },
        )
        .await
        .unwrap();
        assert!(src.describe().starts_with("http-server https://"));
        let addr = src
            .describe()
            .strip_prefix("http-server https://")
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        // A client that trusts exactly the certificate we just generated.
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

        // A wrong or absent token is refused on the same listener. The secret is
        // only ever compared over TLS, which is what makes carrying it acceptable.
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
                "expected 401 for headers {headers:?}"
            );
        }

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[tokio::test]
    async fn a_secret_on_a_plaintext_listener_refuses_to_start() {
        // The secret would be readable in every delivery, and a sender that
        // captured it could inject events the connector would then sign.
        let err = open(
            "127.0.0.1:0",
            "/",
            Some("s3cret".into()),
            Tls {
                cert: None,
                key: None,
                client_ca: None,
            },
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("token requires tls_cert and tls_key"), "{err}");
    }

    #[tokio::test]
    async fn a_half_configured_certificate_pair_refuses_to_start() {
        let err = open(
            "127.0.0.1:0",
            "/",
            None,
            Tls {
                cert: Some("/nonexistent.crt"),
                key: None,
                client_ca: None,
            },
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("both tls_cert and tls_key"), "{err}");
    }

    #[tokio::test]
    async fn client_certificates_need_tls() {
        let err = open(
            "127.0.0.1:0",
            "/",
            None,
            Tls {
                cert: None,
                key: None,
                client_ca: Some("/some/ca.crt"),
            },
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("tls_client_ca needs tls_cert"), "{err}");
    }
}
