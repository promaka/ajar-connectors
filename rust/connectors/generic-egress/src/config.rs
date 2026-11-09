// SPDX-License-Identifier: Apache-2.0
//! Egress config: the shared egress fields, whose `target` is the URL events are posted to,
//! and the consumer's field mapping and delivery settings.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::label::LabelConfig;
use crate::map::Unmapped;

pub type Config = ajar_connector_common::EgressConfig<GenericSettings>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericSettings {
    #[serde(default)]
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
#[serde(default, deny_unknown_fields)]
pub struct Deliver {
    pub headers: BTreeMap<String, String>,
    /// Attempts per event before it is counted as dropped.
    pub attempts: u32,
}

impl Default for Deliver {
    fn default() -> Self {
        Deliver {
            headers: BTreeMap::new(),
            attempts: 2,
        }
    }
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

pub fn load(path: &str) -> anyhow::Result<Config> {
    let cfg = Config::load(path)?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> anyhow::Result<()> {
    let settings = &cfg.connector;
    if settings.mapping.fields.is_empty() {
        anyhow::bail!("[mapping] is empty: nothing would be delivered");
    }
    if settings.deliver.attempts == 0 {
        anyhow::bail!("deliver.attempts must be at least 1");
    }
    for path in settings.mapping.fields.values() {
        crate::map::validate_path(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(settings: &str) -> anyhow::Result<Config> {
        let cfg = Config::parse(&format!(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            egress_subject = "ajar.egress.signed.>"
            egress_verifying_key = "/instance/egress.pub"
            target = "http://127.0.0.1:9000/events"
            {settings}
            "#
        ))?;
        validate(&cfg)?;
        Ok(cfg)
    }

    #[test]
    fn delivery_defaults_apply_without_a_deliver_table() {
        let cfg = cfg("[mapping]\ntrack_id = \"meta:source_uid\"").unwrap();
        assert_eq!(cfg.connector.deliver.attempts, 2);
        assert!(cfg.connector.deliver.headers.is_empty());
    }

    #[test]
    fn empty_mapping_is_refused() {
        let err = cfg("[mapping]").unwrap_err().to_string();
        assert!(err.contains("[mapping] is empty"), "{err}");
    }

    #[test]
    fn unknown_deliver_key_is_refused() {
        let err = cfg("[deliver]\nurl = \"http://elsewhere\"\n[mapping]\nid = \"id\"").unwrap_err();
        assert!(format!("{err:#}").contains("url"), "{err:#}");
    }
}
