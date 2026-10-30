// SPDX-License-Identifier: Apache-2.0
//! The egress config: the governed subject, Core's egress key, and how this
//! node presents itself to the fusion node.

use std::collections::HashMap;

use ajar_connector::VerifyingKey;
use anyhow::Context;
use serde::Deserialize;

pub const EGRESS_PREFIX: &str = "ajar.egress.";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    pub nats_url: String,
    #[serde(default = "default_subject")]
    pub subject: String,
    /// 64-char hex, or a path to a file holding it.
    pub egress_verifying_key: String,
    pub sapient: SapientConfig,
}

fn default_subject() -> String {
    "ajar.egress.signed.>".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SapientConfig {
    /// `host:port`.
    pub fusion_node: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_short_name")]
    pub short_name: String,
    #[serde(default = "default_status_interval_s")]
    pub status_interval_s: f64,
    #[serde(default)]
    pub location: Option<Site>,
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
    #[serde(default)]
    pub classification: HashMap<String, String>,
    #[serde(default = "default_classification")]
    pub default_classification: String,
}

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
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: EgressConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {path}"))?;
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
        let bytes = match hex::decode(v) {
            Ok(bytes) if v.len() == 64 => bytes,
            _ => {
                let raw = std::fs::read(v)
                    .with_context(|| format!("reading egress_verifying_key {v}"))?;
                hex::decode(String::from_utf8_lossy(&raw).trim())
                    .with_context(|| format!("egress_verifying_key file {v} is not hex"))?
            }
        };
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("egress_verifying_key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("egress_verifying_key: {e}"))
    }

    /// The configured node id, or a fresh UUID.
    pub fn node_id(&self) -> String {
        match &self.sapient.node_id {
            Some(id) if !id.trim().is_empty() => id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// A validated config with a real verifying key; `extra` goes under `[sapient]`.
#[cfg(test)]
pub(crate) fn test_config(extra: &str) -> anyhow::Result<EgressConfig> {
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let cfg: EgressConfig = toml::from_str(&format!(
        "nats_url = \"nats://127.0.0.1:4222\"\negress_verifying_key = \"{key}\"\n[sapient]\nfusion_node = \"fusion:7777\"\n{extra}"
    ))?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = test_config("").unwrap();
        assert_eq!(c.subject, "ajar.egress.signed.>");
        assert_eq!(c.sapient.status_interval_s, 5.0);
        assert_eq!(c.sapient.buffer_max, 1000);
        assert_eq!(c.sapient.name, "Ajar");
        assert!(uuid::Uuid::parse_str(&c.node_id()).is_ok());
    }

    #[test]
    fn subject_outside_egress_is_refused() {
        let mut c = test_config("").unwrap();
        c.subject = "ajar.ingest.>".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn bad_values_are_refused_at_load() {
        assert!(test_config("buffer_max = 0").is_err());
        assert!(test_config("status_interval_s = 0").is_err());
        let mut c = test_config("").unwrap();
        c.sapient.fusion_node = "no-port".into();
        assert!(c.validate().is_err());
        assert!(test_config("[sapient.location]\nlat = 91\nlon = 0").is_err());
        assert!(test_config("typo = 1").is_err());
    }
}
