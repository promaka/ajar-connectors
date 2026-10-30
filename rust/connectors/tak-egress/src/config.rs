// SPDX-License-Identifier: Apache-2.0
//! Relay configuration: the NATS egress subject and the TAK target.

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct EgressConfig {
    pub nats_url: String,
    #[serde(default = "default_subject")]
    pub egress_subject: String,
    pub tak: TakConfig,
}

fn default_subject() -> String {
    "ajar.egress.cot.*".to_string()
}

/// A TAK Server's streaming input (`tls://`), or a datagram target such as
/// ATAK's mesh SA multicast group (`udp://`).
#[derive(Debug, Clone, Deserialize)]
pub struct TakConfig {
    pub url: String,
    #[serde(default)]
    pub tls_ca: Option<String>,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Defaults to the host in `url`.
    #[serde(default)]
    pub server_name: Option<String>,
    /// IPv4 address of the multicast interface; unset, the default route.
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "default_multicast_ttl")]
    pub multicast_ttl: u32,
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
}

fn default_buffer_max() -> usize {
    1000
}

fn default_multicast_ttl() -> u32 {
    1
}

impl TakConfig {
    /// `host:port` with any scheme stripped.
    pub fn endpoint(&self) -> &str {
        self.url
            .trim_start_matches("tls://")
            .trim_start_matches("tcp://")
            .trim_start_matches("udp://")
    }

    pub fn is_datagram(&self) -> bool {
        self.url.starts_with("udp://")
    }

    /// The CA, client certificate and key paths, in that order.
    pub fn tls_files(&self) -> anyhow::Result<(&str, &str, &str)> {
        match (&self.tls_ca, &self.tls_cert, &self.tls_key) {
            (Some(ca), Some(cert), Some(key)) => Ok((ca, cert, key)),
            _ => anyhow::bail!(
                "tak.url {:?} is a TAK Server, so tak.tls_ca, tak.tls_cert and tak.tls_key are \
                 required; for ATAK's mesh use url = \"udp://239.2.3.1:6969\"",
                self.url
            ),
        }
    }

    /// The name the server's certificate must present.
    pub fn sni(&self) -> String {
        match &self.server_name {
            Some(n) => n.clone(),
            None => self
                .endpoint()
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| self.endpoint().to_string()),
        }
    }
}

impl EgressConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: EgressConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.tak.buffer_max == 0 {
            anyhow::bail!("tak.buffer_max must be at least 1");
        }
        if !self.tak.is_datagram() {
            self.tak.tls_files()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_sni_from_url() {
        let cfg: EgressConfig = toml::from_str(
            r#"
            nats_url = "tls://nats.example:4222"
            [tak]
            url = "tls://takserver.example:8089"
            tls_ca = "/etc/tak/ca.crt"
            tls_cert = "/etc/tak/client.crt"
            tls_key = "/etc/tak/client.key"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.egress_subject, "ajar.egress.cot.*");
        assert_eq!(cfg.tak.endpoint(), "takserver.example:8089");
        assert_eq!(cfg.tak.sni(), "takserver.example");
        assert_eq!(cfg.tak.buffer_max, 1000);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn multicast_needs_no_certificates() {
        let cfg: EgressConfig = toml::from_str(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            [tak]
            url = "udp://239.2.3.1:6969"
            interface = "192.168.1.20"
            "#,
        )
        .unwrap();
        assert!(cfg.tak.is_datagram());
        assert_eq!(cfg.tak.endpoint(), "239.2.3.1:6969");
        assert_eq!(cfg.tak.multicast_ttl, 1);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tak_server_requires_certificates() {
        let cfg: EgressConfig = toml::from_str(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            [tak]
            url = "tls://takserver.example:8089"
            "#,
        )
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tls_ca"), "{err}");
    }
}
