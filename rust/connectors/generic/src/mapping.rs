// SPDX-License-Identifier: Apache-2.0
//! The `[mapping]` block of a generic connector's TOML.

use std::collections::BTreeMap;

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Json,
    /// Columns named by [`Mapping::columns`].
    Csv,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampFormat {
    #[default]
    Rfc3339,
    EpochMillis,
    EpochSeconds,
}

/// Record fields not named here are ignored. Field settings name a JSON key or
/// a CSV column.
#[derive(Debug, Clone, Deserialize)]
pub struct Mapping {
    pub format: Format,
    #[serde(default = "default_delimiter")]
    pub delimiter: String,
    #[serde(default)]
    pub columns: Vec<String>,
    pub entity_type: String,
    /// Receipt time is used when unset.
    #[serde(default)]
    pub timestamp_field: Option<String>,
    #[serde(default)]
    pub timestamp_format: TimestampFormat,
    #[serde(default)]
    pub confidence_field: Option<String>,
    #[serde(default)]
    pub lat_field: Option<String>,
    #[serde(default)]
    pub lon_field: Option<String>,
    /// Metres.
    #[serde(default)]
    pub alt_field: Option<String>,
    /// Record field to attribute key.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Record field to metadata key.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_delimiter() -> String {
    ",".to_string()
}

#[derive(Debug, Deserialize)]
struct Wrapper {
    mapping: Mapping,
}

impl Mapping {
    /// Reads the `[mapping]` section of a connector config file.
    pub fn load(path: &str) -> anyhow::Result<Mapping> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading mapping from {path}"))?;
        let w: Wrapper =
            toml::from_str(&text).with_context(|| format!("parsing [mapping] in {path}"))?;
        if matches!(w.mapping.format, Format::Csv) && w.mapping.columns.is_empty() {
            anyhow::bail!("mapping.columns is required for CSV (name the fields in order)");
        }
        Ok(w.mapping)
    }
}
