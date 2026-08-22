// SPDX-License-Identifier: Apache-2.0
//! WebSocket client transport — connect out to a feed and take each message as a
//! frame. Requires the `websocket` feature.
//!
//! This is how most modern hosted feeds publish: the provider runs a `wss://`
//! endpoint, you connect, and messages arrive until one side goes away. It is the
//! push counterpart to `rest-poll`, and unlike `http-server` the provider does not
//! need to be able to reach you, which matters when the connector sits behind a
//! firewall with no inbound path.
//!
//! Two details make the difference between a feed that works and one that
//! connects and then sits silent:
//!
//! * Most feeds require a **subscription message** after the handshake. Whatever
//!   `subscribe` is set to is sent on every connect, including reconnects, so a
//!   dropped link resubscribes rather than reconnecting into silence.
//! * Many require **authentication in the handshake headers** rather than in the
//!   URL, so arbitrary headers can be set.
//!
//! Text and binary messages both become frames. Ping, pong and close are handled
//! by the protocol layer and are not passed on. A dropped connection is retried
//! with a bounded backoff rather than ending the connector.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::runtime::FrameSource;

/// First retry delay after a failed or dropped connection.
const RETRY_MIN: Duration = Duration::from_secs(1);
/// Longest the backoff grows to, so a feed that is down for hours is still
/// retried regularly without hammering it.
const RETRY_MAX: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A reconnecting WebSocket client presented as a [`FrameSource`].
pub struct WsSource {
    url: String,
    /// Sent after every successful handshake, if the feed needs one.
    subscribe: Option<String>,
    /// Extra handshake headers, typically authentication.
    headers: Vec<(HeaderName, HeaderValue)>,
    socket: Option<Socket>,
    backoff: Duration,
}

impl WsSource {
    /// Connect, subscribing if configured. Retries with a bounded backoff until it
    /// succeeds, because a feed being briefly unavailable is normal and is not a
    /// reason to stop the connector.
    async fn ensure_connected(&mut self) {
        while self.socket.is_none() {
            match self.dial().await {
                Ok(socket) => {
                    tracing::info!(url = %self.url, "feed connected");
                    self.socket = Some(socket);
                    self.backoff = RETRY_MIN;
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
        let (mut socket, _response) = connect_async(request).await?;
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
            self.ensure_connected().await;
            let socket = self.socket.as_mut().expect("connected above");

            let payload = match socket.next().await {
                Some(Ok(Message::Text(text))) => text.as_bytes().to_vec(),
                Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
                // Control frames carry no feed data; the protocol layer answers
                // pings itself, so there is nothing to hand upward.
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

            // An over-long message is dropped rather than truncated: half a record
            // would parse into a wrong event, which is worse than a missing one.
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

/// Open a WebSocket feed. The URL is validated and the headers are parsed eagerly,
/// so a malformed config fails at startup rather than on the first reconnect. The
/// connection itself is lazy: the first [`FrameSource::recv`] establishes it.
pub fn open(
    url: &str,
    subscribe: Option<String>,
    headers: &std::collections::HashMap<String, String>,
) -> anyhow::Result<WsSource> {
    // Checked explicitly: the request builder accepts things that are not
    // websocket endpoints at all, and a typo should fail at startup rather than
    // on the first connect attempt hours later.
    if !(url.starts_with("ws://") || url.starts_with("wss://")) {
        anyhow::bail!("websocket url must start with ws:// or wss://, got {url:?}");
    }
    url.into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid websocket url {url}: {e}"))?;

    let parsed = headers
        .iter()
        .map(|(name, value)| {
            let name: HeaderName = name
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid header name {name:?}: {e}"))?;
            let value: HeaderValue = value
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid value for header {name}: {e}"))?;
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

    #[test]
    fn accepts_ws_and_wss_urls() {
        assert!(open("ws://feed.example.com/stream", None, &HashMap::new()).is_ok());
        assert!(open("wss://feed.example.com/stream", None, &HashMap::new()).is_ok());
    }

    #[test]
    fn rejects_a_url_that_is_not_a_websocket_endpoint() {
        assert!(open("not-a-url", None, &HashMap::new()).is_err());
        assert!(open("", None, &HashMap::new()).is_err());
        // A plain HTTP endpoint is a common misconfiguration and is caught here
        // rather than at the first connect.
        assert!(open("https://feed.example.com/stream", None, &HashMap::new()).is_err());
    }

    #[test]
    fn headers_are_parsed_at_startup_not_on_reconnect() {
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

    /// Serve one connection on an ephemeral port: echo back whatever subscription
    /// arrives, then send `messages`. Returns the port.
    async fn feed(
        messages: Vec<Message>,
        seen_subscribe: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            // A subscription, if the client sends one, arrives first.
            if let Ok(Some(Ok(Message::Text(text)))) =
                tokio::time::timeout(Duration::from_millis(500), socket.next()).await
            {
                *seen_subscribe.lock().await = Some(text.to_string());
            }
            for m in messages {
                let _ = socket.send(m).await;
            }
            // Hold the connection open so the client does not see an immediate close.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        port
    }

    #[tokio::test]
    async fn text_and_binary_messages_become_frames() {
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let port = feed(
            vec![
                Message::Text("{\"lat\":1.5}".into()),
                Message::Ping(vec![].into()),
                Message::Binary(vec![0xDE, 0xAD].into()),
            ],
            seen.clone(),
        )
        .await;

        let mut src = open(&format!("ws://127.0.0.1:{port}/"), None, &HashMap::new()).unwrap();
        let mut buf = vec![0u8; 1024];

        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"{\"lat\":1.5}");
        // The ping is answered by the protocol layer and never surfaces as a frame.
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn the_subscription_is_sent_after_the_handshake() {
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let port = feed(vec![Message::Text("first".into())], seen.clone()).await;

        let subscribe = r#"{"action":"subscribe","channel":"tracks"}"#;
        let mut src = open(
            &format!("ws://127.0.0.1:{port}/"),
            Some(subscribe.to_string()),
            &HashMap::new(),
        )
        .unwrap();

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
    async fn an_oversized_message_is_dropped_not_truncated() {
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let port = feed(
            vec![
                Message::Binary(vec![0xAA; 128].into()),
                Message::Text("small".into()),
            ],
            seen.clone(),
        )
        .await;

        let mut src = open(&format!("ws://127.0.0.1:{port}/"), None, &HashMap::new()).unwrap();
        // Buffer smaller than the first message: it must be skipped, and the next
        // message delivered intact rather than the connector seeing half a record.
        let mut buf = vec![0u8; 32];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"small");
    }
}
