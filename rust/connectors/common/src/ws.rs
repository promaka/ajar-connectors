// SPDX-License-Identifier: Apache-2.0
//! WebSocket client transport: connect out to a feed; each text or binary
//! message is one frame. `subscribe` is sent after every handshake, so a
//! reconnect resubscribes. A dropped connection is retried with bounded backoff.

use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::runtime::FrameSource;

const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct WsSource {
    url: String,
    subscribe: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
    socket: Option<Socket>,
    backoff: Duration,
}

impl WsSource {
    /// Connect and subscribe, retrying with bounded backoff until it succeeds.
    async fn connect(&mut self) -> Socket {
        loop {
            match self.dial().await {
                Ok(socket) => {
                    tracing::info!(url = %self.url, "feed connected");
                    self.backoff = RETRY_MIN;
                    return socket;
                }
                Err(e) => {
                    tracing::warn!(
                        url = %self.url,
                        error = %e,
                        retry_in = ?self.backoff,
                        "feed connect failed"
                    );
                    tokio::time::sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(RETRY_MAX);
                }
            }
        }
    }

    async fn dial(&self) -> anyhow::Result<Socket> {
        let mut request = self.url.as_str().into_client_request()?;
        for (name, value) in &self.headers {
            request.headers_mut().insert(name, value.clone());
        }
        let (mut socket, _response) = tokio_tungstenite::connect_async(request).await?;
        if let Some(subscribe) = &self.subscribe {
            socket.send(Message::Text(subscribe.clone().into())).await?;
            tracing::debug!(url = %self.url, "subscription sent");
        }
        Ok(socket)
    }
}

#[async_trait::async_trait]
impl FrameSource for WsSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let socket = match &mut self.socket {
                Some(socket) => socket,
                None => {
                    let socket = self.connect().await;
                    self.socket.insert(socket)
                }
            };
            let payload = match socket.next().await {
                Some(Ok(Message::Text(text))) => Bytes::from(text),
                Some(Ok(Message::Binary(bytes))) => bytes,
                // The protocol layer answers pings itself.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Close(frame))) => {
                    tracing::info!(url = %self.url, ?frame, "feed closed the connection");
                    self.socket = None;
                    continue;
                }
                Some(Err(e)) => {
                    tracing::warn!(url = %self.url, error = %e, "feed error, reconnecting");
                    self.socket = None;
                    continue;
                }
                None => {
                    tracing::info!(url = %self.url, "feed ended, reconnecting");
                    self.socket = None;
                    continue;
                }
            };

            if payload.len() > buf.len() {
                tracing::warn!(
                    url = %self.url,
                    bytes = payload.len(),
                    limit = buf.len(),
                    "dropping oversized message"
                );
                continue;
            }
            buf[..payload.len()].copy_from_slice(&payload);
            return Ok(payload.len());
        }
    }

    fn describe(&self) -> String {
        format!("ws-client {}", self.url)
    }
}

/// Open a WebSocket feed. The URL and headers are checked now, so a bad config
/// fails at startup; the first [`FrameSource::recv`] connects.
pub fn open(
    url: &str,
    subscribe: Option<String>,
    headers: &std::collections::HashMap<String, String>,
) -> anyhow::Result<WsSource> {
    // The request builder accepts URLs that are not websocket endpoints.
    if !(url.starts_with("ws://") || url.starts_with("wss://")) {
        anyhow::bail!("websocket url must start with ws:// or wss://, got {url:?}");
    }
    url.into_client_request()
        .with_context(|| format!("invalid websocket url {url}"))?;

    let parsed = headers
        .iter()
        .map(|(name, value)| {
            let name: HeaderName = name
                .parse()
                .with_context(|| format!("invalid header name {name:?}"))?;
            let value: HeaderValue = value
                .parse()
                .with_context(|| format!("invalid value for header {name}"))?;
            Ok((name, value))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(WsSource {
        url: url.to_string(),
        subscribe,
        headers: parsed,
        socket: None,
        backoff: RETRY_MIN,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    type Seen = Arc<Mutex<Option<String>>>;

    fn local(port: u16, subscribe: Option<String>) -> WsSource {
        open(
            &format!("ws://127.0.0.1:{port}/"),
            subscribe,
            &HashMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn accepts_ws_and_wss_urls() {
        assert!(open("ws://feed.example.com/stream", None, &HashMap::new()).is_ok());
        assert!(open("wss://feed.example.com/stream", None, &HashMap::new()).is_ok());
    }

    #[test]
    fn rejects_non_websocket_urls() {
        assert!(open("not-a-url", None, &HashMap::new()).is_err());
        assert!(open("", None, &HashMap::new()).is_err());
        assert!(open("https://feed.example.com/stream", None, &HashMap::new()).is_err());
    }

    #[test]
    fn headers_are_parsed_at_startup() {
        let good = HashMap::from([("Authorization".to_string(), "Bearer abc123".to_string())]);
        assert!(open("wss://x/y", None, &good).is_ok());

        let bad_name = HashMap::from([("bad header".to_string(), "v".to_string())]);
        assert!(open("wss://x/y", None, &bad_name).is_err());

        let bad_value = HashMap::from([("X-Token".to_string(), "line\nbreak".to_string())]);
        assert!(open("wss://x/y", None, &bad_value).is_err());
    }

    #[test]
    fn describes_itself_by_url() {
        let src = open("wss://feed.example.com/stream", None, &HashMap::new()).unwrap();
        assert_eq!(src.describe(), "ws-client wss://feed.example.com/stream");
    }

    #[test]
    fn backoff_grows_and_is_bounded() {
        let mut d = RETRY_MIN;
        for _ in 0..10 {
            d = (d * 2).min(RETRY_MAX);
        }
        assert_eq!(d, RETRY_MAX);
        assert!(RETRY_MIN < RETRY_MAX);
    }

    /// Serve one connection on an ephemeral port: record the subscription, if
    /// one arrives, then send `messages`. Returns the port.
    async fn feed(messages: Vec<Message>, seen_subscribe: Seen) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            if let Ok(Some(Ok(Message::Text(text)))) =
                tokio::time::timeout(Duration::from_millis(500), socket.next()).await
            {
                *seen_subscribe.lock().await = Some(text.to_string());
            }
            for m in messages {
                let _ = socket.send(m).await;
            }
            // Hold the connection open past the test.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        port
    }

    #[tokio::test]
    async fn text_and_binary_messages_become_frames() {
        let seen = Seen::default();
        let port = feed(
            vec![
                Message::Text("{\"lat\":1.5}".into()),
                Message::Ping(vec![].into()),
                Message::Binary(vec![0xDE, 0xAD].into()),
            ],
            seen.clone(),
        )
        .await;

        let mut src = local(port, None);
        let mut buf = vec![0u8; 1024];

        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"{\"lat\":1.5}");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &[0xDE, 0xAD],
            "the ping never surfaces as a frame"
        );
    }

    #[tokio::test]
    async fn subscription_is_sent_after_the_handshake() {
        let seen = Seen::default();
        let port = feed(vec![Message::Text("first".into())], seen.clone()).await;

        let subscribe = r#"{"action":"subscribe","channel":"tracks"}"#;
        let mut src = local(port, Some(subscribe.to_string()));

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        assert_eq!(
            seen.lock().await.as_deref(),
            Some(subscribe),
            "a feed that needs a subscription must receive it, or it sends nothing"
        );
    }

    #[tokio::test]
    async fn oversized_message_is_dropped_not_truncated() {
        let seen = Seen::default();
        let port = feed(
            vec![
                Message::Binary(vec![0xAA; 128].into()),
                Message::Text("small".into()),
            ],
            seen.clone(),
        )
        .await;

        let mut src = local(port, None);
        let mut buf = vec![0u8; 32];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"small",
            "the oversized message is skipped whole"
        );
    }
}
