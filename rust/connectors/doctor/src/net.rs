// SPDX-License-Identifier: Apache-2.0
//! Reaching the NATS endpoint: URL parsing, DNS, TCP, and the cleartext INFO
//! preflight a NATS server sends before any TLS upgrade.

use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The host and port a `nats_url` names, with the scheme's TLS demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// True when the URL scheme itself is `tls://`.
    pub tls_scheme: bool,
}

impl Endpoint {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parse the first endpoint out of a `nats_url`. Accepts `nats://host:port`,
/// `tls://host:port`, bare `host:port`, an optional `user:pass@` block, and a
/// comma-separated list (only the first entry is probed; a broken first entry
/// is what the connector would hit too).
pub fn parse_url(url: &str) -> anyhow::Result<Endpoint> {
    let first = url
        .split(',')
        .next()
        .expect("split yields at least one item")
        .trim();
    let lower = first.to_ascii_lowercase();
    let (tls_scheme, rest) = if let Some(r) = lower.strip_prefix("tls://") {
        (true, &first[first.len() - r.len()..])
    } else if let Some(r) = lower.strip_prefix("nats://") {
        (false, &first[first.len() - r.len()..])
    } else {
        (false, first)
    };
    // Credentials in the URL are the operator's business; strip them for dialing.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| anyhow!("{p:?} is not a port number"))?,
        ),
        None => (rest, 4222),
    };
    if host.is_empty() {
        return Err(anyhow!("no host in nats_url {url:?}"));
    }
    Ok(Endpoint {
        host: host.to_string(),
        port,
        tls_scheme,
    })
}

/// What a TCP dial found out.
#[derive(Debug)]
pub enum Dial {
    Connected(TcpStream),
    /// The name did not resolve at all.
    NoDns(String),
    /// Resolved, but nothing answered: refused or timed out, with the detail.
    NoAnswer(String),
}

/// Resolve and connect, with a bounded wait. Distinguishes "the name is wrong
/// for this network" from "the name is right but nothing is listening", which
/// are fixed by different people.
pub async fn dial(ep: &Endpoint, timeout: Duration) -> Dial {
    let addrs = match tokio::net::lookup_host(ep.addr()).await {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => return Dial::NoDns(e.to_string()),
    };
    if addrs.is_empty() {
        return Dial::NoDns("the name resolved to no addresses".into());
    }
    let mut last = String::new();
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Dial::Connected(stream),
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => last = format!("{addr}: no answer within {}s", timeout.as_secs()),
        }
    }
    Dial::NoAnswer(last)
}

/// The server's cleartext greeting, when it sends one. In the standard NATS
/// handshake the server speaks first with `INFO {json}` before any TLS
/// upgrade; a server in TLS-first mode sends nothing until the handshake.
#[derive(Debug, Default)]
pub struct ServerInfo {
    pub tls_required: bool,
    pub tls_available: bool,
    /// The raw JSON, for the curious.
    pub raw: String,
}

/// Read the INFO greeting off a fresh connection, if the server sends one
/// within the wait. `Ok(None)` means silence, which is what a TLS-first
/// server looks like; it is not an error.
pub async fn read_info(
    stream: &mut TcpStream,
    wait: Duration,
) -> anyhow::Result<Option<ServerInfo>> {
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(0)) => return Err(anyhow!("the server closed the connection immediately")),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(anyhow!("reading the server greeting: {e}")),
        Err(_) => return Ok(None),
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    parse_info(&text).map(Some)
}

pub fn parse_info(text: &str) -> anyhow::Result<ServerInfo> {
    let rest = text.trim_start().strip_prefix("INFO ").ok_or_else(|| {
        anyhow!(
            "the server did not greet with INFO (got {:?})",
            text.chars().take(40).collect::<String>()
        )
    })?;
    let line = rest.lines().next().unwrap_or(rest);
    let v: serde_json::Value =
        serde_json::from_str(line.trim()).context("the INFO greeting is not valid JSON")?;
    Ok(ServerInfo {
        tls_required: v["tls_required"].as_bool().unwrap_or(false),
        tls_available: v["tls_available"].as_bool().unwrap_or(false),
        raw: line.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_url_shape_a_config_can_carry() {
        let ep = parse_url("tls://nats.example.mil:4443").unwrap();
        assert_eq!(
            ep,
            Endpoint {
                host: "nats.example.mil".into(),
                port: 4443,
                tls_scheme: true
            }
        );
        let ep = parse_url("nats://127.0.0.1:4222").unwrap();
        assert!(!ep.tls_scheme);
        // Bare host defaults to the NATS port.
        assert_eq!(parse_url("localhost").unwrap().port, 4222);
        // Credentials are stripped, never printed back.
        let ep = parse_url("nats://user:secret@10.0.0.5:4222").unwrap();
        assert_eq!(ep.host, "10.0.0.5");
        // Only the first entry of a list is probed.
        assert_eq!(parse_url("nats://a:4222,nats://b:4222").unwrap().host, "a");
        // Scheme casing does not matter; the host's own casing is preserved.
        assert_eq!(parse_url("TLS://UpperHost:4443").unwrap().host, "UpperHost");
    }

    #[test]
    fn rejects_the_urls_that_would_confuse_the_connector_too() {
        assert!(parse_url("nats://host:notaport").is_err());
        assert!(parse_url("tls://:4222").is_err());
    }

    #[test]
    fn reads_the_tls_flags_out_of_a_real_greeting() {
        let info = parse_info(
            "INFO {\"server_id\":\"X\",\"tls_required\":true,\"tls_available\":true}\r\n",
        )
        .unwrap();
        assert!(info.tls_required);
        assert!(info.tls_available);
    }

    #[test]
    fn a_non_nats_service_is_named_not_guessed_at() {
        let err = parse_info("HTTP/1.1 400 Bad Request\r\n").unwrap_err();
        assert!(err.to_string().contains("did not greet with INFO"));
    }
}
