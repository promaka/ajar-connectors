// SPDX-License-Identifier: Apache-2.0
//! Reaching the NATS endpoint: URL parsing, DNS, TCP, and the cleartext INFO
//! preflight a NATS server sends before any TLS upgrade.

use std::time::Duration;

use anyhow::Context;
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

/// Every endpoint of a comma-separated `nats_url` failover list. Each entry is
/// `nats://host:port`, `tls://host:port` or bare `host:port`, with an optional
/// `user:pass@`; the port defaults to 4222.
pub fn parse_urls(url: &str) -> anyhow::Result<Vec<Endpoint>> {
    url.split(',').map(|u| parse_one(u.trim())).collect()
}

fn parse_one(entry: &str) -> anyhow::Result<Endpoint> {
    let lower = entry.to_ascii_lowercase();
    let (tls_scheme, rest) = if let Some(r) = lower.strip_prefix("tls://") {
        (true, &entry[entry.len() - r.len()..])
    } else if let Some(r) = lower.strip_prefix("nats://") {
        (false, &entry[entry.len() - r.len()..])
    } else {
        (false, entry)
    };
    // Credentials are stripped for dialing.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("{p:?} is not a port number"))?,
        ),
        None => (rest, 4222),
    };
    if host.is_empty() {
        return Err(anyhow::anyhow!("no host in nats_url entry {entry:?}"));
    }
    Ok(Endpoint {
        host: host.to_string(),
        port,
        tls_scheme,
    })
}

#[derive(Debug)]
pub enum Dial {
    Connected(TcpStream),
    /// The name did not resolve at all.
    NoDns(String),
    /// Resolved, but nothing answered: refused or timed out, with the detail.
    NoAnswer(String),
}

/// Resolve and connect, with a bounded wait. A name that does not resolve and
/// a name nothing answers on are fixed by different people.
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

/// The cleartext `INFO {json}` a NATS server sends before any TLS upgrade.
#[derive(Debug, Default)]
pub struct ServerInfo {
    pub tls_required: bool,
    pub tls_available: bool,
}

/// The INFO greeting off a fresh connection. `Ok(None)` is silence within the
/// wait, which is what a TLS-first server looks like.
pub async fn read_info(
    stream: &mut TcpStream,
    wait: Duration,
) -> anyhow::Result<Option<ServerInfo>> {
    let mut buf = vec![0u8; 8192];
    let n = match tokio::time::timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            return Err(anyhow::anyhow!(
                "the server closed the connection immediately"
            ))
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(anyhow::anyhow!("reading the server greeting: {e}")),
        Err(_) => return Ok(None),
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    parse_info(&text).map(Some)
}

pub fn parse_info(text: &str) -> anyhow::Result<ServerInfo> {
    let rest = text.trim_start().strip_prefix("INFO ").ok_or_else(|| {
        anyhow::anyhow!(
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(url: &str) -> Endpoint {
        parse_urls(url).unwrap().remove(0)
    }

    #[test]
    fn tls_scheme_host_and_port() {
        assert_eq!(
            first("tls://nats.example.mil:4443"),
            Endpoint {
                host: "nats.example.mil".into(),
                port: 4443,
                tls_scheme: true
            }
        );
        assert!(!first("nats://127.0.0.1:4222").tls_scheme);
    }

    #[test]
    fn bare_host_defaults_to_nats_port() {
        assert_eq!(first("localhost").port, 4222);
    }

    #[test]
    fn credentials_are_stripped() {
        assert_eq!(first("nats://user:secret@10.0.0.5:4222").host, "10.0.0.5");
    }

    #[test]
    fn failover_list_keeps_order() {
        let eps = parse_urls("nats://a:4222, nats://b:4222").unwrap();
        let hosts: Vec<&str> = eps.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, ["a", "b"]);
    }

    #[test]
    fn scheme_case_ignored_host_case_kept() {
        assert_eq!(first("TLS://UpperHost:4443").host, "UpperHost");
    }

    #[test]
    fn bad_port_or_empty_host_rejected() {
        assert!(parse_urls("nats://host:notaport").is_err());
        assert!(parse_urls("tls://:4222").is_err());
    }

    #[test]
    fn reads_tls_flags_from_greeting() {
        let info = parse_info(
            "INFO {\"server_id\":\"X\",\"tls_required\":true,\"tls_available\":true}\r\n",
        )
        .unwrap();
        assert!(info.tls_required);
        assert!(info.tls_available);
    }

    #[test]
    fn non_nats_service_named() {
        let err = parse_info("HTTP/1.1 400 Bad Request\r\n").unwrap_err();
        assert!(err.to_string().contains("did not greet with INFO"));
    }
}
