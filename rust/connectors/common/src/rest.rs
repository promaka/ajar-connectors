// SPDX-License-Identifier: Apache-2.0
//! REST-poll transport: request a URL on an interval. Each response body is one frame or, with
//! `records`, each element of the array that JSON pointer names is one frame, kept as the exact
//! bytes it had in the response.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::value::RawValue;

use crate::config::{HttpMethod, RestPollOptions};
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

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RecordsError {
    #[error("response is not JSON: {0}")]
    Json(String),
    #[error("pointer must be empty or start with '/'")]
    Relative,
    #[error("pointer has a '~' not followed by 0 or 1")]
    Escape,
    #[error("nothing at {0:?}")]
    Missing(String),
    #[error("value at the pointer is not an array")]
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
    method: Method,
    body: Option<Bytes>,
    records: Option<String>,
    interval: Duration,
    credentials: Credentials,
    pending: VecDeque<Bytes>,
    first: bool,
}

impl RestPollSource {
    /// One request, retried once with a fresh token when the server refuses the held one.
    async fn poll(&mut self) -> Result<Bytes, PollError> {
        let mut retried = false;
        loop {
            let mut req = self.http.request(self.method.clone(), &self.url);
            if let Some(body) = &self.body {
                req = req
                    .header(CONTENT_TYPE, "application/json")
                    .body(body.clone());
            }
            req = match &mut self.credentials {
                Credentials::None => req,
                Credentials::Header(value) => req.header(AUTHORIZATION, value.clone()),
                Credentials::OAuth(tokens) => {
                    req.header(AUTHORIZATION, tokens.authorization().await?)
                }
            };
            let mut resp = req.send().await?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED && !retried {
                if let Credentials::OAuth(tokens) = &mut self.credentials {
                    tokens.invalidate();
                    retried = true;
                    continue;
                }
            }
            if !status.is_success() {
                return Err(PollError::Status(status));
            }
            if resp
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
            {
                return Err(PollError::TooLarge);
            }
            let mut body = BytesMut::new();
            while let Some(chunk) = resp.chunk().await? {
                if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(PollError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(body.freeze());
        }
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
                (Ok(body), Some(pointer)) => records(&body, pointer).map_err(PollError::from),
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
        format!(
            "rest-poll {} {} every {:?}",
            self.method, self.url, self.interval
        )
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
        method: match opts.method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
        },
        body: opts.body.clone().map(Bytes::from),
        records: opts.records.clone(),
        interval: Duration::from_secs(opts.interval_secs.max(1)),
        credentials,
        pending: VecDeque::new(),
        first: true,
    })
}

/// The reference tokens of an RFC 6901 pointer, unescaped.
pub(crate) fn pointer_tokens(pointer: &str) -> Result<Vec<String>, RecordsError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let rest = pointer.strip_prefix('/').ok_or(RecordsError::Relative)?;
    rest.split('/')
        .map(|token| {
            let mut out = String::with_capacity(token.len());
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c != '~' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('0') => out.push('~'),
                    Some('1') => out.push('/'),
                    _ => return Err(RecordsError::Escape),
                }
            }
            Ok(out)
        })
        .collect()
}

/// The elements of the array at `pointer`, each sliced from `body` without copying.
fn records(body: &Bytes, pointer: &str) -> Result<Vec<Bytes>, RecordsError> {
    let json = |e: serde_json::Error| RecordsError::Json(e.to_string());
    let text = std::str::from_utf8(body).map_err(|e| RecordsError::Json(e.to_string()))?;
    let mut value: &RawValue = serde_json::from_str(text).map_err(json)?;
    for token in pointer_tokens(pointer)? {
        let missing = || RecordsError::Missing(token.clone());
        value = if value.get().trim_start().starts_with('[') {
            let items: Vec<&RawValue> = serde_json::from_str(value.get()).map_err(json)?;
            let index: usize = token.parse().map_err(|_| missing())?;
            items.get(index).copied().ok_or_else(missing)?
        } else {
            let fields: HashMap<String, &RawValue> =
                serde_json::from_str(value.get()).map_err(|_| missing())?;
            fields.get(&token).copied().ok_or_else(missing)?
        };
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
    use crate::http_mock::{MockServer, Reply};
    use crate::oauth::OAuthClient;

    fn options(server: &MockServer) -> RestPollOptions {
        RestPollOptions {
            url: server.url("/tracks"),
            interval_secs: 1,
            method: HttpMethod::Get,
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
    fn empty_pointer_names_a_top_level_array() {
        let body = Bytes::from_static(br#" [{"id":1},{"id":2}]"#);
        assert_eq!(records(&body, "").unwrap().len(), 2);
    }

    #[test]
    fn pointer_walks_array_indexes_and_escapes() {
        let body = Bytes::from_static(br#"{"pages":[{"a/b~c":[{"id":1}]}]}"#);
        assert_eq!(records(&body, "/pages/0/a~1b~0c").unwrap().len(), 1);
    }

    #[test]
    fn missing_member_is_named() {
        let body = Bytes::from_static(br#"{"data":{}}"#);
        assert_eq!(
            records(&body, "/data/tracks"),
            Err(RecordsError::Missing("tracks".into()))
        );
    }

    #[test]
    fn non_array_target_is_refused() {
        let body = Bytes::from_static(br#"{"tracks":{"id":1}}"#);
        assert_eq!(records(&body, "/tracks"), Err(RecordsError::NotArray));
    }

    #[test]
    fn malformed_pointers_are_refused() {
        assert_eq!(pointer_tokens("tracks"), Err(RecordsError::Relative));
        assert_eq!(pointer_tokens("/a~2"), Err(RecordsError::Escape));
    }

    #[tokio::test]
    async fn whole_body_is_one_frame() {
        let server = MockServer::start(vec![Reply::json(200, r#"{"id":1}"#)]).await;
        let mut source = open(&options(&server)).unwrap();
        assert_eq!(next(&mut source).await, r#"{"id":1}"#);
        assert_eq!(server.requests()[0].method, "GET");
    }

    #[tokio::test]
    async fn post_sends_the_body_and_auth_header() {
        let server = MockServer::start(vec![Reply::json(200, "[{}]")]).await;
        let mut opts = options(&server);
        opts.method = HttpMethod::Post;
        opts.body = Some(r#"{"since":"2026-01-01T00:00:00Z"}"#.into());
        opts.auth_header = Some("Bearer fixed".into());
        opts.records = Some(String::new());
        let mut source = open(&opts).unwrap();
        assert_eq!(next(&mut source).await, "{}");
        let request = &server.requests()[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, r#"{"since":"2026-01-01T00:00:00Z"}"#);
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("authorization"), Some("Bearer fixed"));
    }

    #[tokio::test]
    async fn refused_token_is_replaced_and_retried() {
        let token = |t: &str| {
            Reply::json(
                200,
                &format!(r#"{{"access_token":"{t}","token_type":"Bearer","expires_in":300}}"#),
            )
        };
        let server = MockServer::start(vec![
            token("stale"),
            Reply::json(401, "{}"),
            token("fresh"),
            Reply::json(200, r#"{"id":1}"#),
        ])
        .await;
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret.path(), "s3cret").unwrap();
        let mut opts = options(&server);
        opts.oauth = Some(OAuthClient {
            token_url: server.url("/token"),
            client_id: "radar-1".into(),
            client_secret_file: secret.path().to_str().unwrap().into(),
            scope: None,
        });
        let mut source = open(&opts).unwrap();
        assert_eq!(next(&mut source).await, r#"{"id":1}"#);
        let requests = server.requests();
        assert_eq!(requests[3].path, "/tracks");
        assert_eq!(requests[3].header("authorization"), Some("Bearer fresh"));
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
