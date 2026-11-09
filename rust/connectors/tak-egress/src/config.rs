// SPDX-License-Identifier: Apache-2.0
//! Relay configuration: the shared egress fields, whose `target` is the TAK target, and the
//! TAK settings. `egress_verifying_key` is not read: the CoT channel carries Core's renderings,
//! which are not signed.

use serde::Deserialize;

pub type EgressConfig = ajar_connector_common::EgressConfig<TakSettings>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakSettings {
    #[serde(default)]
    pub tak: TakConfig,
}

/// The way the relay reaches its target: a TAK Server's streaming input (`tls://`), or a datagram
/// target such as ATAK's mesh SA multicast group (`udp://`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TakConfig {
    pub tls_ca: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Defaults to the host in the target.
    pub server_name: Option<String>,
    /// IPv4 address of the multicast interface; unset, the default route.
    pub interface: Option<String>,
    pub multicast_ttl: u32,
    pub buffer_max: usize,
}

impl Default for TakConfig {
    fn default() -> Self {
        TakConfig {
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            server_name: None,
            interface: None,
            multicast_ttl: 1,
            buffer_max: 1000,
        }
    }
}

/// The target's `host:port` with any scheme stripped.
pub fn endpoint(target: &str) -> &str {
    target
        .trim_start_matches("tls://")
        .trim_start_matches("tcp://")
        .trim_start_matches("udp://")
}

pub fn is_datagram(target: &str) -> bool {
    target.starts_with("udp://")
}

impl TakConfig {
    /// The CA, client certificate and key paths, in that order.
    pub fn tls_files(&self, target: &str) -> anyhow::Result<(&str, &str, &str)> {
        match (&self.tls_ca, &self.tls_cert, &self.tls_key) {
            (Some(ca), Some(cert), Some(key)) => Ok((ca, cert, key)),
            _ => anyhow::bail!(
                "target {target:?} is a TAK Server, so tak.tls_ca, tak.tls_cert and tak.tls_key \
                 are required; for ATAK's mesh use target = \"udp://239.2.3.1:6969\""
            ),
        }
    }

    /// The name the server's certificate must present.
    pub fn sni(&self, target: &str) -> String {
        match &self.server_name {
            Some(name) => name.clone(),
            None => endpoint(target)
                .rsplit_once(':')
                .map(|(host, _)| host.to_string())
                .unwrap_or_else(|| endpoint(target).to_string()),
        }
    }
}

pub fn load(path: &str) -> anyhow::Result<EgressConfig> {
    let cfg = EgressConfig::load(path)?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &EgressConfig) -> anyhow::Result<()> {
    let tak = &cfg.connector.tak;
    if tak.buffer_max == 0 {
        anyhow::bail!("tak.buffer_max must be at least 1");
    }
    if !is_datagram(&cfg.target) {
        tak.tls_files(&cfg.target)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target: &str, tak: &str) -> EgressConfig {
        EgressConfig::parse(&format!(
            r#"
            nats_url = "tls://nats.example:4222"
            egress_subject = "ajar.egress.cot.*"
            egress_verifying_key = "/instance/egress.pub"
            target = "{target}"
            {tak}
            "#
        ))
        .unwrap()
    }

    #[test]
    fn defaults_and_sni_from_the_target() {
        let cfg = config(
            "tls://takserver.example:8089",
            r#"
            [tak]
            tls_ca = "/etc/tak/ca.crt"
            tls_cert = "/etc/tak/client.crt"
            tls_key = "/etc/tak/client.key"
            "#,
        );
        assert_eq!(endpoint(&cfg.target), "takserver.example:8089");
        assert_eq!(cfg.connector.tak.sni(&cfg.target), "takserver.example");
        assert_eq!(cfg.connector.tak.buffer_max, 1000);
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn multicast_needs_no_tak_table() {
        let cfg = config("udp://239.2.3.1:6969", "");
        assert!(is_datagram(&cfg.target));
        assert_eq!(endpoint(&cfg.target), "239.2.3.1:6969");
        assert_eq!(cfg.connector.tak.multicast_ttl, 1);
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn tak_server_requires_certificates() {
        let cfg = config("tls://takserver.example:8089", "");
        let err = validate(&cfg).unwrap_err().to_string();
        assert!(err.contains("tls_ca"), "{err}");
    }
}
