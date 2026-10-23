// SPDX-License-Identifier: Apache-2.0
//! The egress config: where governed events come from, the key that proves
//! they are Core's, and how this connector presents itself to the fusion node.

use std::collections::HashMap;

use ajar_connector::VerifyingKey;
use serde::Deserialize;

/// Every egress subject sits under this prefix.
pub const EGRESS_PREFIX: &str = "ajar.egress.";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    /// Ajar's NATS endpoint (`tls://…` in production, with the subscribe-only
    /// client certificate as this consumer's transport identity).
    pub nats_url: String,
    /// Governed egress subject to consume: `ajar.egress.<format>.>` or
    /// narrower. The envelope's event carries the position and attributes
    /// whatever the rendered format, so any format the deployment egresses
    /// will do; `ajar.egress.json.>` is the usual one.
    #[serde(default = "default_subject")]
    pub subject: String,
    /// Core's egress verifying key (64-char hex, or a path to a file holding
    /// it). Every payload is verified under it before it is mapped; nothing
    /// that fails reaches the fusion node.
    pub egress_verifying_key: String,
    pub sapient: SapientConfig,
}

fn default_subject() -> String {
    "ajar.egress.json.>".to_string()
}

/// How this connector appears on the fusion node.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SapientConfig {
    /// The fusion node's SAPIENT endpoint, `host:port`.
    pub fusion_node: String,
    /// This node's identity, a UUID the fusion node sees in every message.
    /// Unset, a fresh one is made at start-up; set it so re-registrations
    /// after a restart are the same node.
    #[serde(default)]
    pub node_id: Option<String>,
    /// The node's name and short name, as the fusion node displays them.
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_short_name")]
    pub short_name: String,
    /// Seconds between status reports. Declared to the fusion node at
    /// registration, so it knows when this node has gone quiet.
    #[serde(default = "default_status_interval_s")]
    pub status_interval_s: f64,
    /// This node's own position, reported in each status report. Optional:
    /// a relay has no sensor position of its own.
    #[serde(default)]
    pub location: Option<Site>,
    /// Reports held while the fusion node is unreachable. Beyond it the
    /// oldest is dropped and counted.
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
    /// The SAPIENT classification reported for each Ajar entity type, on top
    /// of the built-in table (`mim:aircraft` is `Aircraft`, and so on). An
    /// event's own `sapient_classification` or `object_class` attribute
    /// wins over both.
    #[serde(default)]
    pub classification: HashMap<String, String>,
    /// The classification for an entity type nothing names.
    #[serde(default = "default_classification")]
    pub default_classification: String,
}

/// A WGS-84 position, degrees and metres.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub lat: f64,
    pub lon: f64,
    #[serde(default)]
    pub alt_m: f64,
}

fn default_name() -> String {
    "Ajar".to_string()
}

fn default_short_name() -> String {
    "AJAR".to_string()
}

fn default_status_interval_s() -> f64 {
    5.0
}

fn default_buffer_max() -> usize {
    1000
}

fn default_classification() -> String {
    "Unknown".to_string()
}

impl EgressConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        let cfg: EgressConfig =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.subject.starts_with(EGRESS_PREFIX) {
            anyhow::bail!(
                "subject {:?} is not under {EGRESS_PREFIX}: this connector consumes governed egress only",
                self.subject
            );
        }
        if self.sapient.buffer_max == 0 {
            anyhow::bail!("sapient.buffer_max must be at least 1");
        }
        if !(self.sapient.status_interval_s.is_finite() && self.sapient.status_interval_s > 0.0) {
            anyhow::bail!("sapient.status_interval_s must be a positive number of seconds");
        }
        if self.sapient.fusion_node.rsplit_once(':').is_none() {
            anyhow::bail!(
                "sapient.fusion_node {:?} must be host:port",
                self.sapient.fusion_node
            );
        }
        if let Some(site) = &self.sapient.location {
            if !(-90.0..=90.0).contains(&site.lat) || !(-180.0..=180.0).contains(&site.lon) {
                anyhow::bail!("sapient.location is off the globe");
            }
        }
        self.verifying_key()?;
        Ok(())
    }

    /// The egress key, from hex or from a file of hex.
    pub fn verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        let v = self.egress_verifying_key.trim();
        let bytes = if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(v).expect("checked hex")
        } else {
            let raw = std::fs::read(v)
                .map_err(|e| anyhow::anyhow!("reading egress_verifying_key {v}: {e}"))?;
            hex::decode(String::from_utf8_lossy(&raw).trim())
                .map_err(|e| anyhow::anyhow!("egress_verifying_key file {v} is not hex: {e}"))?
        };
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("egress_verifying_key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("egress_verifying_key: {e}"))
    }

    /// This node's identity: the configured one, or a fresh UUID.
    pub fn node_id(&self) -> String {
        match &self.sapient.node_id {
            Some(id) if !id.trim().is_empty() => id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real verifying key: the public half of a fixed test seed.
    fn key() -> String {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn cfg(extra: &str) -> anyhow::Result<EgressConfig> {
        let key = key();
        let cfg: EgressConfig = toml::from_str(&format!(
            "nats_url = \"nats://127.0.0.1:4222\"\negress_verifying_key = \"{key}\"\n[sapient]\nfusion_node = \"fusion:7777\"\n{extra}"
        ))?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn defaults_are_sensible_and_the_subject_stays_under_egress() {
        let c = cfg("").unwrap();
        assert_eq!(c.subject, "ajar.egress.json.>");
        assert_eq!(c.sapient.status_interval_s, 5.0);
        assert_eq!(c.sapient.buffer_max, 1000);
        assert_eq!(c.sapient.name, "Ajar");
        assert!(uuid::Uuid::parse_str(&c.node_id()).is_ok());
        assert!(cfg("subject = \"ajar.ingest.>\"").is_err());
    }

    #[test]
    fn bad_values_are_refused_at_load() {
        assert!(cfg("buffer_max = 0").is_err());
        assert!(cfg("status_interval_s = 0").is_err());
        assert!(cfg("fusion_node = \"no-port\"").is_err());
        assert!(cfg("[sapient.location]\nlat = 91\nlon = 0").is_err());
        assert!(cfg("typo = 1").is_err());
    }
}
