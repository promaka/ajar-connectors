// SPDX-License-Identifier: Apache-2.0
//! Egress config: the governed subject, Core's egress key, the consumer's
//! field mapping and the delivery endpoint.

use std::collections::BTreeMap;

use ajar_connector::VerifyingKey;
use anyhow::Context;
use serde::Deserialize;

use crate::label::LabelConfig;
use crate::map::Unmapped;

/// Every egress subscription lives under this prefix, which keeps the
/// effector cue channel (`ajar.cue.>`) out of reach.
pub const EGRESS_PREFIX: &str = "ajar.egress.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub nats_url: String,
    pub subject: String,
    /// 64-char hex, or a path to a file of 32 raw bytes or hex.
    pub egress_verifying_key: String,
    pub deliver: Deliver,
    pub mapping: Mapping,
    #[serde(default)]
    pub unmapped: Unmapped,
    #[serde(default)]
    pub confidentiality_label: Option<LabelConfig>,
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deliver {
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Attempts per event before it is counted as dropped.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
}

/// Consumer field name to event path.
// Free-form: every key is a consumer field name, so unknown fields are allowed.
#[derive(Debug, Deserialize)]
pub struct Mapping {
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
}

fn default_buffer_max() -> usize {
    1000
}

fn default_attempts() -> u32 {
    2
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let s = self.subject.trim();
        if !s.starts_with(EGRESS_PREFIX) {
            anyhow::bail!(
                "subject {s:?} must start with {EGRESS_PREFIX:?}: egress consumes governed \
                 output only, and the effector cue channel is out of reach"
            );
        }
        if self.mapping.fields.is_empty() {
            anyhow::bail!("[mapping] is empty: nothing would be delivered");
        }
        if self.deliver.attempts == 0 {
            anyhow::bail!("deliver.attempts must be at least 1");
        }
        for path in self.mapping.fields.values() {
            crate::map::validate_path(path)?;
        }
        Ok(())
    }

    pub fn verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        let v = self.egress_verifying_key.trim();
        let bytes = match hex::decode(v) {
            Ok(inline) if v.len() == 64 => inline,
            _ => {
                let raw = std::fs::read(v)
                    .with_context(|| format!("reading egress_verifying_key {v}"))?;
                if raw.len() == 32 {
                    raw
                } else {
                    hex::decode(String::from_utf8_lossy(&raw).trim()).map_err(|_| {
                        anyhow::anyhow!("egress key {v}: neither 32 raw bytes nor hex")
                    })?
                }
            }
        };
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("egress key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).context("egress key invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(subject: &str) -> Result<Config, anyhow::Error> {
        let text = format!(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            subject = "{subject}"
            egress_verifying_key = "{}"
            [deliver]
            url = "http://127.0.0.1:9000/events"
            [mapping]
            track_id = "meta:source_uid"
            "#,
            "ab".repeat(32)
        );
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn egress_subject_is_accepted() {
        assert!(cfg("ajar.egress.json.>").is_ok());
        assert!(cfg("ajar.egress.cot.coastal-radar").is_ok());
    }

    #[test]
    fn cue_channel_is_unreachable() {
        for s in [
            "ajar.cue.fire",
            "ajar.cue.>",
            "ajar.>",
            ">",
            "ajar.ingest.>",
        ] {
            let err = cfg(s).unwrap_err().to_string();
            assert!(err.contains("must start with"), "{s}: {err}");
        }
    }
}
