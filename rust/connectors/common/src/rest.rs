// SPDX-License-Identifier: Apache-2.0
//! REST-poll transport: request a URL on an interval, as a POST when a body is set. Each
//! response body is one frame or, with `records`, each element of the array at that path is one
//! frame, kept as the exact bytes it had in the response.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::value::RawValue;

use crate::config::RestPollOptions;
use crate::oauth::{OAuthError, TokenSource};
use crate::runtime::FrameSource;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response read. A response split into records can be far larger than one frame.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum PollError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("server answered {0}")]
    Status(StatusCode),
    #[error("response over {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error(transparent)]
    Records(#[from] RecordsError),
}

#[derive(Debug, thiserror::Error)]
enum RecordsError {
    #[error("response is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("nothing at {0:?}")]
    Missing(String),
    #[error("value at the records path is not an array")]
    NotArray,
}

enum Credentials {
    None,
    Header(HeaderValue),
    OAuth(Box<TokenSource>),
}

pub struct RestPollSource {
    http: reqwest::Client,
    url: String,
    body: Option<Bytes>,
    records: Option<String>,
    interval: Duration,
    credentials: Credentials,
    pending: VecDeque<Bytes>,
    first: bool,
}

impl RestPollSource {
    /// One request. A 401 drops the held token, so the next poll fetches a new one.
    async fn poll(&mut self) -> Result<Bytes, PollError> {
        let mut req = match &self.body {
            Some(body) => self
                .http
                .post(&self.url)
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone()),
            None => self.http.get(&self.url),
        };
        req = match &mut self.credentials {
            Credentials::None => req,
            Credentials::Header(value) => req.header(AUTHORIZATION, value.clone()),
            Credentials::OAuth(tokens) => req.header(AUTHORIZATION, tokens.authorization().await?),
        };
        let mut resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            if let (StatusCode::UNAUTHORIZED, Credentials::OAuth(tokens)) =
                (status, &mut self.credentials)
            {
                tokens.invalidate();
            }
            return Err(PollError::Status(status));
        }
        let mut body = BytesMut::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(PollError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }
}

#[async_trait::async_trait]
impl FrameSource for RestPollSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                if frame.len() > buf.len() {
                    tracing::warn!(
                        url = %self.url,
                        len = frame.len(),
                        cap = buf.len(),
                        "record over frame limit dropped"
                    );
                    continue;
                }
                buf[..frame.len()].copy_from_slice(&frame);
                return Ok(frame.len());
            }
            if self.first {
                self.first = false;
            } else {
                tokio::time::sleep(self.interval).await;
            }
            let frames = match (self.poll().await, &self.records) {
                (Ok(body), Some(path)) => records(&body, path).map_err(PollError::from),
                (Ok(body), None) => Ok(vec![body]),
                (Err(e), _) => Err(e),
            };
            match frames {
                Ok(frames) => self.pending.extend(frames),
                Err(e) => tracing::warn!(url = %self.url, error = %e, "poll failed"),
            }
        }
    }

    fn describe(&self) -> String {
        format!("rest-poll {} every {:?}", self.url, self.interval)
    }
}

/// Builds a REST-poll source. The first request is sent on the first read.
pub fn open(opts: &RestPollOptions) -> anyhow::Result<RestPollSource> {
    crate::nats::install_crypto_provider();
    let http = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("building HTTP client")?;
    let credentials = match (&opts.auth_header, &opts.oauth) {
        (Some(value), _) => {
            let mut value = HeaderValue::from_str(value)
                .context("transport.auth_header is not a valid header value")?;
            value.set_sensitive(true);
            Credentials::Header(value)
        }
        (None, Some(client)) => Credentials::OAuth(Box::new(
            TokenSource::new(http.clone(), client.clone()).context("transport.oauth")?,
        )),
        (None, None) => Credentials::None,
    };
    Ok(RestPollSource {
        http,
        url: opts.url.clone(),
        body: opts.body.clone().map(Bytes::from),
        records: opts.records.clone(),
        interval: Duration::from_secs(opts.interval_secs.max(1)),
        credentials,
        pending: VecDeque::new(),
        first: true,
    })
}

/// The elements of the array at `path`, `""` or `/`-separated member names, each sliced from
/// `body` without copying.
fn records(body: &Bytes, path: &str) -> Result<Vec<Bytes>, RecordsError> {
    let mut value: &RawValue = serde_json::from_slice(body)?;
    for name in path.split('/').skip(1) {
        let mut members: HashMap<String, &RawValue> = serde_json::from_str(value.get())
            .map_err(|_| RecordsError::Missing(name.to_string()))?;
        value = members
            .remove(name)
            .ok_or_else(|| RecordsError::Missing(name.to_string()))?;
    }
    let items: Vec<&RawValue> =
        serde_json::from_str(value.get()).map_err(|_| RecordsError::NotArray)?;
    Ok(items
        .into_iter()
        .map(|item| body.slice_ref(item.get().as_bytes()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_mock::{secret_file, token_reply, MockServer, Reply};
    use crate::oauth::OAuthClient;

    fn options(server: &MockServer) -> RestPollOptions {
        RestPollOptions {
            url: server.url("/tracks"),
            interval_secs: 1,
            body: None,
            auth_header: None,
            oauth: None,
            records: None,
        }
    }

    async fn next(source: &mut RestPollSource) -> String {
        let mut buf = vec![0u8; crate::MAX_FRAME_BYTES];
        let n = source.recv(&mut buf).await.unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    #[test]
    fn records_keep_their_exact_bytes() {
        let body =
            Bytes::from_static(br#"{"data":{"tracks":[ {"id": 1,  "lat":60.0} ,{"id":2}]}}"#);
        let frames = records(&body, "/data/tracks").unwrap();
        assert_eq!(frames, [&br#"{"id": 1,  "lat":60.0}"#[..], br#"{"id":2}"#]);
    }

    #[test]
    fn empty_path_names_a_top_level_array() {
        let body = Bytes::from_static(br#" [{"id":1},{"id":2}]"#);
        assert_eq!(records(&body, "").unwrap().len(), 2);
    }

    #[test]
    fn missing_member_is_named() {
        let body = Bytes::from_static(br#"{"data":{}}"#);
        let err = records(&body, "/data/tracks").unwrap_err();
        assert!(
            matches!(&err, RecordsError::Missing(name) if name == "tracks"),
            "{err}"
        );
    }

    #[test]
    fn non_array_target_is_refused() {
        let body = Bytes::from_static(br#"{"tracks":{"id":1}}"#);
        let err = records(&body, "/tracks").unwrap_err();
        assert!(matches!(err, RecordsError::NotArray), "{err}");
    }

    #[tokio::test]
    async fn whole_body_is_one_frame() {
        let server = MockServer::start(vec![Reply::json(200, r#"{"id":1}"#)]).await;
        let mut source = open(&options(&server)).unwrap();
        assert_eq!(next(&mut source).await, r#"{"id":1}"#);
        assert_eq!(server.requests()[0].method, "GET");
    }

    #[tokio::test]
    async fn body_is_posted_as_json() {
        let server = MockServer::start(vec![Reply::json(200, "{}")]).await;
        let mut opts = options(&server);
        opts.body = Some(r#"{"since":"2026-01-01T00:00:00Z"}"#.into());
        next(&mut open(&opts).unwrap()).await;
        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, r#"{"since":"2026-01-01T00:00:00Z"}"#);
        assert_eq!(request.header("content-type"), Some("application/json"));
    }

    #[tokio::test]
    async fn auth_header_is_sent() {
        let server = MockServer::start(vec![Reply::json(200, "{}")]).await;
        let mut opts = options(&server);
        opts.auth_header = Some("Bearer fixed".into());
        next(&mut open(&opts).unwrap()).await;
        assert_eq!(
            server.requests()[0].header("authorization"),
            Some("Bearer fixed")
        );
    }

    #[tokio::test]
    async fn refused_token_is_replaced_on_the_next_poll() {
        let server = MockServer::start(vec![
            token_reply("stale", 300),
            Reply::json(401, "{}"),
            token_reply("fresh", 300),
            Reply::json(200, r#"{"id":1}"#),
        ])
        .await;
        let secret = secret_file("s3cret");
        let mut opts = options(&server);
        opts.oauth = Some(OAuthClient {
            token_url: server.url("/token"),
            client_id: "radar-1".into(),
            client_secret_file: secret.path().to_str().unwrap().into(),
            scope: None,
        });
        let mut source = open(&opts).unwrap();
        assert_eq!(next(&mut source).await, r#"{"id":1}"#);
        assert_eq!(
            server.requests()[3].header("authorization"),
            Some("Bearer fresh")
        );
    }

    #[tokio::test]
    async fn oversized_record_is_dropped_and_the_next_delivered() {
        let big = format!(r#"{{"pad":"{}"}}"#, "x".repeat(crate::MAX_FRAME_BYTES));
        let server =
            MockServer::start(vec![Reply::json(200, &format!(r#"[{big},{{"id":2}}]"#))]).await;
        let mut opts = options(&server);
        opts.records = Some(String::new());
        let mut source = open(&opts).unwrap();
        assert_eq!(next(&mut source).await, r#"{"id":2}"#);
    }
}
