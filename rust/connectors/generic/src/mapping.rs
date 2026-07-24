// SPDX-License-Identifier: Apache-2.0
//! The declarative field mapping — the whole "no code" surface.
//!
//! A `[mapping]` block in the connector's TOML says how a native JSON object or
//! CSV row becomes a canonical event: which fields are the location and
//! timestamp, which governed attributes to carry, and which native identifiers to
//! pass through as ungoverned metadata. A whole class of simple sources needs only
//! this — no Rust.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The native record format.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// One JSON object per frame.
    Json,
    /// One delimited row per frame, columns named by [`Mapping::columns`].
    Csv,
}

/// How a mapped timestamp field is expressed on the wire.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampFormat {
    /// Already RFC 3339 — used as-is.
    #[default]
    Rfc3339,
    /// Milliseconds since the Unix epoch.
    EpochMillis,
    /// Seconds since the Unix epoch.
    EpochSeconds,
}

/// The field mapping. Fields not named here are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Mapping {
    /// Native record format.
    pub format: Format,
    /// CSV field delimiter (CSV only).
    #[serde(default = "default_delimiter")]
    pub delimiter: String,
    /// CSV column names, in order (CSV only). Referenced by the field settings.
    #[serde(default)]
    pub columns: Vec<String>,
    /// The Ajar entity type every event gets (must be registered in the ontology).
    pub entity_type: String,
    /// Source field holding the observation time; if unset, receipt time is used.
    #[serde(default)]
    pub timestamp_field: Option<String>,
    /// How that field is encoded.
    #[serde(default)]
    pub timestamp_format: TimestampFormat,
    /// Source field holding a detection/track confidence. Values in `[0,1]` are
    /// used as-is; a value above 1 is treated as a percentage (`87` → `0.87`).
    #[serde(default)]
    pub confidence_field: Option<String>,
    /// Source fields for the WGS-84 position (latitude/longitude; altitude
    /// optional). A location is emitted only when both lat and lon are present.
    #[serde(default)]
    pub lat_field: Option<String>,
    #[serde(default)]
    pub lon_field: Option<String>,
    #[serde(default)]
    pub alt_field: Option<String>,
    /// Governed attributes: `source_field = "ajar_attribute_key"`. These are
    /// type-validated by the entity's ontology schema.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Ungoverned passthrough: `source_field = "metadata_key"`. Native identifiers
    /// and the long tail live here (never the id — that is always a fresh UUIDv7).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_delimiter() -> String {
    ",".to_string()
}

/// The `[mapping]` wrapper, so the same TOML file carries both the connector
/// config (read by `common`) and the mapping (read here).
#[derive(Debug, Deserialize)]
struct Wrapper {
    mapping: Mapping,
}

impl Mapping {
    /// Load the `[mapping]` section from the connector's config file.
    pub fn load(path: &str) -> anyhow::Result<Mapping> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading mapping from {path}: {e}"))?;
        let w: Wrapper = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing [mapping] in {path}: {e}"))?;
        if matches!(w.mapping.format, Format::Csv) && w.mapping.columns.is_empty() {
            anyhow::bail!("mapping.columns is required for CSV (name the fields in order)");
        }
        Ok(w.mapping)
    }
}
