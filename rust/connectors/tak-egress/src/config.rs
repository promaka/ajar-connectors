// SPDX-License-Identifier: Apache-2.0
//! Egress relay configuration. Deliberately its own shape (not the ingest
//! [`ajar_connector_common::Config`]): an egress relay has no signing key, no
//! entity mapping, and no field transport — it holds two endpoints and a buffer
//! bound.

use serde::Deserialize;

/// The relay's configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct EgressConfig {
    /// Ajar's NATS endpoint (`tls://…` in production, with the `AJAR_TLS_*` env
    /// holding this relay's subscribe-only mTLS identity).
    pub nats_url: String,
    /// Egress subject to subscribe (`*` = per-source token).
    #[serde(default = "default_subject")]
    pub egress_subject: String,
    /// The TAK Server side.
    pub tak: TakConfig,
}

fn default_subject() -> String {
    "ajar.egress.cot.*".to_string()
}

/// Where TAK is: a TAK Server's streaming input and this relay's client
/// identity on it, or ATAK's mesh multicast group with no server at all.
#[derive(Debug, Clone, Deserialize)]
pub struct TakConfig {
    /// `tls://host:8089` for a TAK Server's streaming input (the standard
    /// port), or `udp://239.2.3.1:6969` for ATAK's mesh SA multicast group,
    /// which every TAK client on the same network reads with no server. Any
    /// `udp://ip:port` is one datagram per event.
    pub url: String,
    /// CA bundle that signed the TAK Server's certificate. Required for
    /// `tls://`, unused for `udp://`.
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// This relay's client certificate, enrolled with the TAK Server.
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// The private key for `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Server name for TLS verification (SNI). Defaults to the host in `url`.
    #[serde(default)]
    pub server_name: Option<String>,
    /// For multicast: the interface the TAK clients share, as its IPv4
    /// address. Unset, the system's default route carries the group.
    #[serde(default)]
    pub interface: Option<String>,
    /// For multicast: how many hops the datagrams may cross. 1 keeps them on
    /// the local network, which is where ATAK's mesh lives.
    #[serde(default = "default_multicast_ttl")]
    pub multicast_ttl: u32,
    /// Events buffered in memory while the TAK Server is unreachable. On
    /// overflow the OLDEST event is dropped and the gap metric increments —
    /// bounded and lossy by design for a live picture feed.
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

    /// Whether `url` names a datagram target rather than a TAK Server.
    pub fn is_datagram(&self) -> bool {
        self.url.starts_with("udp://")
    }

    /// The three TLS files, or why the config cannot reach a TAK Server.
    pub fn tls_files(&self) -> anyhow::Result<(&str, &str, &str)> {
        match (&self.tls_ca, &self.tls_cert, &self.tls_key) {
            (Some(ca), Some(cert), Some(key)) => Ok((ca, cert, key)),
            _ => anyhow::bail!(
                "tak.url {:?} is a TAK Server, so tak.tls_ca, tak.tls_cert and tak.tls_key are \
                 required (the server's CA and this relay's enrolled client certificate and key); \
                 for ATAK's mesh with no server, use url = \"udp://239.2.3.1:6969\"",
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
    /// Load and validate a config file.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        let cfg: EgressConfig =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The checks a config must pass before the relay starts.
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
    fn parses_and_derives_sni_from_url() {
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
    fn a_mesh_multicast_target_needs_no_certificates_and_a_server_does() {
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
