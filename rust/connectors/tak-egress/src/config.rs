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

/// The TAK Server streaming input and this relay's client identity on it.
#[derive(Debug, Clone, Deserialize)]
pub struct TakConfig {
    /// TAK Server streaming input, `host:port` (a `tls://` prefix is accepted
    /// and stripped). The standard streaming port is 8089.
    pub url: String,
    /// CA bundle that signed the TAK Server's certificate.
    pub tls_ca: String,
    /// This relay's client certificate, enrolled with the TAK Server.
    pub tls_cert: String,
    /// The private key for `tls_cert`.
    pub tls_key: String,
    /// Server name for TLS verification (SNI). Defaults to the host in `url`.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Events buffered in memory while the TAK Server is unreachable. On
    /// overflow the OLDEST event is dropped and the gap metric increments —
    /// bounded and lossy by design for a live picture feed.
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
}

fn default_buffer_max() -> usize {
    1000
}

impl TakConfig {
    /// `host:port` with any `tls://` scheme stripped.
    pub fn endpoint(&self) -> &str {
        self.url
            .trim_start_matches("tls://")
            .trim_start_matches("tcp://")
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
        if cfg.tak.buffer_max == 0 {
            anyhow::bail!("tak.buffer_max must be at least 1");
        }
        Ok(cfg)
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
    }
}
