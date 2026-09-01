// SPDX-License-Identifier: Apache-2.0
//! Egress config: which governed subjects to consume, the key that proves Core
//! governed them, the shape the consumer wants, and where to deliver it.

use std::collections::BTreeMap;

use ajar_connector::VerifyingKey;
use serde::Deserialize;

/// The subject prefix every egress subscription must live under. Enforcing the
/// prefix — rather than blocklisting what is forbidden — means the effector cue
/// channel (`ajar.cue.>`) is unreachable by construction, not by vigilance: a
/// track-share tool must never be one wildcard away from fire commands.
pub const EGRESS_PREFIX: &str = "ajar.egress.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Ajar's NATS endpoint (`tls://…` in production, with the subscribe-only
    /// client certificate as this consumer's transport identity).
    pub nats_url: String,
    /// Governed egress subject to consume: `ajar.egress.<format>.>` or
    /// narrower. Must sit under [`EGRESS_PREFIX`]; the certificate decides what
    /// it may actually see.
    pub subject: String,
    /// Core's egress verifying key (64-char hex, or a path to a file holding
    /// it). From the operator's handover pack. Every payload is verified under
    /// this key before it is mapped or delivered; producer signatures do not
    /// survive egress by design, so this is the one key that matters here.
    pub egress_verifying_key: String,
    /// Where governed JSON is delivered.
    pub deliver: Deliver,
    /// Consumer-shaped output: consumer field name = event path.
    pub mapping: Mapping,
    /// Governed content the mapping does not name: `include` (delivered under
    /// `unmapped`) or `refuse` (event rejected, counted). There is no silent
    /// drop; a mapping cannot strip markings or content on the way out.
    #[serde(default = "default_unmapped")]
    pub unmapped: crate::map::Unmapped,
    /// Optional: project policy tags into a STANAG 4774-shaped
    /// confidentiality label on every delivered object. Opt-in per
    /// deployment; absent means delivered objects are unchanged.
    #[serde(default)]
    pub confidentiality_label: Option<crate::label::LabelConfig>,
    /// Events held in memory while the consumer is unreachable. On overflow the
    /// OLDEST is dropped and `egress_gap_dropped_total` increments — bounded
    /// and lossy for a live picture feed, mirroring ingress.
    #[serde(default = "default_buffer_max")]
    pub buffer_max: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deliver {
    /// Consumer endpoint; each event is one HTTP POST of one JSON object.
    pub url: String,
    /// Extra request headers, typically authentication the consumer issued.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Attempts per event before it is counted failed and dropped. Kept small
    /// so total delivery time stays inside one ack window when the durable
    /// leg lands (30s ack_wait: two attempts at <=10s each, plus backoff).
    #[serde(default = "default_attempts")]
    pub attempts: u32,
}

/// Consumer field name (left) = event path (right). Paths: `id`, `source_id`,
/// `entity_type`, `timestamp`, `lat`, `lon`, `alt_m`, `confidence`,
/// `attr:<name>`, `meta:<name>`.
// No deny_unknown_fields here: the mapping IS a free-form map of consumer
// field names, and every one of them is deliberately "unknown".
#[derive(Debug, Deserialize)]
pub struct Mapping {
    #[serde(flatten)]
    pub fields: BTreeMap<String, String>,
}

fn default_buffer_max() -> usize {
    1000
}
fn default_unmapped() -> crate::map::Unmapped {
    crate::map::Unmapped::Include
}
fn default_attempts() -> u32 {
    2
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// The rules a subscription must satisfy before a socket is opened.
    fn validate(&self) -> anyhow::Result<()> {
        let s = self.subject.trim();
        if !s.starts_with(EGRESS_PREFIX) {
            anyhow::bail!(
                "subject {s:?} must start with {EGRESS_PREFIX:?}: egress consumes governed \
                 output only, and the effector cue channel is out of reach by construction"
            );
        }
        // Defence in depth: the prefix rule above already excludes it, but a
        // future edit must trip over this line before it can widen the rule.
        if s.starts_with("ajar.cue.") || s == "ajar.>" || s == ">" {
            anyhow::bail!("subject {s:?} would reach the effector cue channel: refused");
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

    /// The egress key, from inline hex or a file of hex/raw bytes.
    pub fn verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        let v = self.egress_verifying_key.trim();
        let bytes = if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(v).expect("checked hex")
        } else {
            let raw = std::fs::read(v)
                .map_err(|e| anyhow::anyhow!("reading egress_verifying_key {v}: {e}"))?;
            if raw.len() == 32 {
                raw
            } else {
                hex::decode(String::from_utf8_lossy(&raw).trim())
                    .map_err(|_| anyhow::anyhow!("egress key {v}: neither 32 raw bytes nor hex"))?
            }
        };
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("egress key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("egress key invalid: {e}"))
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
    fn an_egress_subject_is_accepted() {
        assert!(cfg("ajar.egress.json.>").is_ok());
        assert!(cfg("ajar.egress.cot.coastal-radar").is_ok());
    }

    #[test]
    fn the_cue_channel_is_unreachable() {
        for s in [
            "ajar.cue.fire",
            "ajar.cue.>",
            "ajar.>",
            ">",
            "ajar.ingest.>",
        ] {
            let err = cfg(s).unwrap_err().to_string();
            assert!(
                err.contains("must start with") || err.contains("refused"),
                "{s}: {err}"
            );
        }
    }
}
