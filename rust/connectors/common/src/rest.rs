// SPDX-License-Identifier: Apache-2.0
//! REST-poll transport — GET an HTTP endpoint on an interval, each response body a
//! frame. For pull-only REST/JSON APIs. Requires the `rest-poll` feature. The
//! response must fit the runtime's frame buffer; larger/paginated APIs want a
//! purpose-built connector.

use std::time::Duration;

use crate::runtime::FrameSource;

/// Polls an HTTP endpoint, yielding each response body as a frame.
pub struct RestPollSource {
    client: reqwest::Client,
    url: String,
    interval: Duration,
    auth_header: Option<String>,
    first: bool,
}

#[async_trait::async_trait]
impl FrameSource for RestPollSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Space out polls; the first fires immediately.
            if self.first {
                self.first = false;
            } else {
                tokio::time::sleep(self.interval).await;
            }
            let mut req = self.client.get(&self.url);
            if let Some(auth) = &self.auth_header {
                req = req.header(reqwest::header::AUTHORIZATION, auth);
            }
            match req.send().await.and_then(|r| r.error_for_status()) {
                Ok(resp) => match resp.bytes().await {
                    Ok(body) => {
                        let n = body.len().min(buf.len());
                        if body.len() > buf.len() {
                            tracing::warn!(
                                url = %self.url,
                                got = body.len(),
                                cap = buf.len(),
                                "response truncated to frame buffer"
                            );
                        }
                        buf[..n].copy_from_slice(&body[..n]);
                        return Ok(n);
                    }
                    Err(e) => tracing::warn!(url = %self.url, error = %e, "reading body failed"),
                },
                Err(e) => tracing::warn!(url = %self.url, error = %e, "poll failed"),
            }
        }
    }

    fn describe(&self) -> String {
        format!("rest-poll {} every {:?}", self.url, self.interval)
    }
}

/// Build a REST-poll source.
pub fn open(
    url: &str,
    interval_secs: u64,
    auth_header: Option<&str>,
) -> anyhow::Result<RestPollSource> {
    Ok(RestPollSource {
        client: reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("building HTTP client: {e}"))?,
        url: url.to_string(),
        interval: Duration::from_secs(interval_secs.max(1)),
        auth_header: auth_header.map(str::to_string),
        first: true,
    })
}
