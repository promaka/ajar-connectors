// SPDX-License-Identifier: Apache-2.0
//! The egress config: the shared egress fields, whose `target` is the fusion node's
//! `host:port`, and how this node presents itself to the fusion node.

use std::collections::HashMap;

use serde::Deserialize;

pub type EgressConfig = ajar_connector_common::EgressConfig<SapientSettings>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SapientSettings {
    #[serde(default)]
    pub sapient: SapientConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SapientConfig {
    pub node_id: Option<String>,
    pub name: String,
    pub short_name: String,
    pub status_interval_s: f64,
    pub location: Option<Site>,
    pub buffer_max: usize,
    pub classification: HashMap<String, String>,
    pub default_classification: String,
}

impl Default for SapientConfig {
    fn default() -> Self {
        SapientConfig {
            node_id: None,
            name: "Ajar".to_string(),
            short_name: "AJAR".to_string(),
            status_interval_s: 5.0,
            location: None,
            buffer_max: 1000,
            classification: HashMap::new(),
            default_classification: "Unknown".to_string(),
        }
    }
}

impl SapientConfig {
    /// The configured node id, or a fresh UUID.
    pub fn node_id(&self) -> String {
        match &self.node_id {
            Some(id) if !id.trim().is_empty() => id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub lat: f64,
    pub lon: f64,
    #[serde(default)]
    pub alt_m: f64,
}

pub fn load(path: &str) -> anyhow::Result<EgressConfig> {
    let cfg = EgressConfig::load(path)?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &EgressConfig) -> anyhow::Result<()> {
    let sapient = &cfg.connector.sapient;
    if sapient.buffer_max == 0 {
        anyhow::bail!("sapient.buffer_max must be at least 1");
    }
    if !(sapient.status_interval_s.is_finite() && sapient.status_interval_s > 0.0) {
        anyhow::bail!("sapient.status_interval_s must be a positive number of seconds");
    }
    if cfg.target.rsplit_once(':').is_none() {
        anyhow::bail!(
            "target {:?} must be the fusion node's host:port",
            cfg.target
        );
    }
    if let Some(site) = &sapient.location {
        if !(-90.0..=90.0).contains(&site.lat) || !(-180.0..=180.0).contains(&site.lon) {
            anyhow::bail!("sapient.location is off the globe");
        }
    }
    Ok(())
}

/// A validated config; `extra` goes under `[sapient]`.
#[cfg(test)]
pub(crate) fn test_config(extra: &str) -> anyhow::Result<EgressConfig> {
    let cfg = EgressConfig::parse(&format!(
        "nats_url = \"nats://127.0.0.1:4222\"\n\
         egress_subject = \"ajar.egress.signed.>\"\n\
         egress_verifying_key = \"/instance/egress.pub\"\n\
         target = \"fusion:7777\"\n\
         [sapient]\n{extra}"
    ))?;
    validate(&cfg)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = test_config("").unwrap();
        let sapient = &c.connector.sapient;
        assert_eq!(sapient.status_interval_s, 5.0);
        assert_eq!(sapient.buffer_max, 1000);
        assert_eq!(sapient.name, "Ajar");
        assert!(uuid::Uuid::parse_str(&sapient.node_id()).is_ok());
    }

    #[test]
    fn bad_values_are_refused_at_load() {
        assert!(test_config("buffer_max = 0").is_err());
        assert!(test_config("status_interval_s = 0").is_err());
        let mut c = test_config("").unwrap();
        c.target = "no-port".into();
        assert!(validate(&c).is_err());
        assert!(test_config("[sapient.location]\nlat = 91\nlon = 0").is_err());
        assert!(test_config("typo = 1").is_err());
        assert!(test_config("fusion_node = \"fusion:7777\"").is_err());
    }
}
