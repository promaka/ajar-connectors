// SPDX-License-Identifier: Apache-2.0
//! The `[mapping]` block of a generic connector's TOML.

use std::collections::{BTreeMap, BTreeSet};

use ajar_connector_common::ontology::Declared;
use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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

/// Record fields not named here are ignored. A field setting names a JSON key, an RFC 6901
/// JSON pointer starting with `/`, or a CSV column.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub format: Format,
    #[serde(default = "default_delimiter")]
    pub delimiter: String,
    #[serde(default)]
    pub columns: Vec<String>,
    pub entity_type: String,
    #[serde(default)]
    pub entity_type_field: Option<String>,
    #[serde(default)]
    pub entity_types: BTreeMap<String, String>,
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
    #[serde(default)]
    pub values: BTreeMap<String, BTreeMap<String, String>>,
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
        w.mapping
            .validate()
            .with_context(|| format!("checking [mapping] in {path}"))?;
        Ok(w.mapping)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.format == Format::Csv && self.columns.is_empty() {
            anyhow::bail!("mapping.columns is required for CSV (name the fields in order)");
        }
        if self.entity_type_field.is_some() && self.entity_types.is_empty() {
            anyhow::bail!("mapping.entity_type_field needs a [mapping.entity_types] table");
        }
        let mapped: BTreeSet<&str> = self.attributes.values().map(String::as_str).collect();
        if let Some(key) = self.values.keys().find(|k| !mapped.contains(k.as_str())) {
            anyhow::bail!("[mapping.values.{key}] names no attribute in [mapping.attributes]");
        }
        if self.format == Format::Csv {
            let pointer = [
                &self.entity_type_field,
                &self.timestamp_field,
                &self.confidence_field,
                &self.lat_field,
                &self.lon_field,
                &self.alt_field,
            ]
            .into_iter()
            .flatten()
            .chain(self.attributes.keys())
            .chain(self.metadata.keys())
            .find(|f| f.starts_with('/'));
            if let Some(field) = pointer {
                anyhow::bail!("JSON pointer {field:?} in a CSV mapping");
            }
        }
        Ok(())
    }

    /// One declaration per entity type the mapping can emit, for the startup ontology check:
    /// every mapped attribute, `hostility` from `default_hostility`, and each value table.
    pub fn declared(&self, default_hostility: Option<&str>) -> Vec<Declared> {
        let attributes: Vec<String> = self.attributes.values().cloned().collect();
        let mut fixed_values: Vec<(String, String)> = self
            .values
            .iter()
            .flat_map(|(key, table)| table.values().map(|v| (key.clone(), v.clone())))
            .collect();
        if let Some(hostility) = default_hostility {
            fixed_values.push(("hostility".to_string(), hostility.to_string()));
        }
        self.entity_types()
            .into_iter()
            .map(|entity_type| Declared {
                entity_type: entity_type.to_string(),
                attributes: attributes.clone(),
                fixed_values: fixed_values.clone(),
            })
            .collect()
    }

    /// Every entity type the mapping can emit, the fallback first.
    pub fn entity_types(&self) -> Vec<&str> {
        let mut types = vec![self.entity_type.as_str()];
        for t in self.entity_types.values() {
            if !types.contains(&t.as_str()) {
                types.push(t);
            }
        }
        types
    }
}
