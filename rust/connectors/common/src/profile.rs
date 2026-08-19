// SPDX-License-Identifier: Apache-2.0
//! Emit the connector profile the operator registers, derived from the config
//! the connector already parses and the key it already holds.
//!
//! Onboarding otherwise asks a vendor to hand-write this document — or, for the
//! no-code connector, to write Rust to produce it. Every field is already known
//! at startup, so transcribing it is work that only introduces typos. An
//! `entity_type` misspelled by hand is not rejected: Core's graceful mode
//! discards the unrecognised value, and the connector runs perfectly while its
//! tracks never appear.
//!
//! `allowed_entity_types` are **prefixes**, matched by Core with `starts_with`.
//! That is what makes an open-ended connector expressible: `tak-cot` maps two
//! CoT battle dimensions to `mim:` types and falls back to `x:cot:<type>` for
//! everything else, an unbounded set that no enumeration could cover.
//!
//! Rate limits are deliberately absent. They are the operator's policy, not the
//! connector's to assert; a connector declaring its own would be asking, not
//! declaring. Core supplies them.

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::config::Config;

/// The profile document, matching Core's `ConnectorSpec` schema.
#[derive(Debug, Serialize, PartialEq)]
pub struct Profile {
    /// Schema generation this document is written against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    /// The connector's registered identity.
    pub source_id: String,
    /// Entity-type **prefixes** this connector may emit; Core matches with
    /// `starts_with`, so `"x:cot:"` admits every `x:cot:<type>` fallback.
    pub allowed_entity_types: Vec<String>,
    /// Advisory ceiling: the transport's frame cap. Core enforces its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    /// The public half of the connector's signing key.
    pub verifying_key_hex: String,
}

impl Profile {
    /// Derive the profile from a loaded config, the connector's verifying key,
    /// and the entity-type prefixes that connector can emit.
    pub fn derive(
        cfg: &Config,
        verifying_key: &VerifyingKey,
        entity_type_prefixes: &[&str],
    ) -> Self {
        // Operator overrides can introduce types the connector would not emit on
        // its own, so their prefixes belong in the profile too — otherwise a
        // mapping that works locally is refused by Core.
        let mut allowed: Vec<String> = entity_type_prefixes
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for mapped in cfg.entity_map.values() {
            if !allowed.iter().any(|p| mapped.starts_with(p.as_str())) {
                allowed.push(mapped.clone());
            }
        }
        allowed.sort();
        allowed.dedup();

        Self {
            contract: Some("v1".to_string()),
            source_id: cfg.source_id.clone(),
            allowed_entity_types: allowed,
            max_payload_bytes: Some(crate::MAX_FRAME_BYTES as u64),
            verifying_key_hex: hex::encode(verifying_key.to_bytes()),
        }
    }

    /// The document as the operator receives it.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("profile is plain data")
    }
}

/// Whether this invocation should print the profile and exit instead of running.
pub fn requested(args: &[String]) -> bool {
    args.iter().any(|a| a == "--profile")
}

/// Load the key named by the config and emit the profile.
pub fn emit(cfg: &Config, entity_type_prefixes: &[&str]) -> anyhow::Result<String> {
    let key = crate::key::load(&cfg.signing_key_path)?;
    Ok(Profile::derive(cfg, &key.verifying_key(), entity_type_prefixes).to_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn cfg(overrides: &[(&str, &str)]) -> Config {
        let mut c: Config = toml::from_str(
            r#"
            source_id = "acme-1"
            nats_url = "nats://127.0.0.1:4222"
            signing_key_path = "/dev/null"
            [transport]
            kind = "udp"
            bind = "0.0.0.0:1"
            "#,
        )
        .unwrap();
        for (k, v) in overrides {
            c.entity_map.insert((*k).to_string(), (*v).to_string());
        }
        c
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x47; 32])
    }

    #[test]
    fn the_key_is_the_public_half_of_the_signing_key() {
        let k = key();
        let p = Profile::derive(&cfg(&[]), &k.verifying_key(), &["mim:"]);
        assert_eq!(
            p.verifying_key_hex,
            hex::encode(k.verifying_key().to_bytes())
        );
        assert_eq!(p.verifying_key_hex.len(), 64);
        // The private half must never appear in a document handed to an operator.
        assert!(!p.to_json().contains(&hex::encode(k.to_bytes())));
    }

    #[test]
    fn rate_limits_are_never_asserted_by_the_connector() {
        let json = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]).to_json();
        assert!(!json.contains("rate_capacity"));
        assert!(!json.contains("rate_refill_per_sec"));
    }

    #[test]
    fn entity_types_are_prefixes_so_an_open_fallback_is_expressible() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:", "x:cot:"]);
        assert_eq!(p.allowed_entity_types, vec!["mim:", "x:cot:"]);
        // Core matches with starts_with, so the unbounded fallback is covered.
        assert!("x:cot:a-f-G-U-C-I".starts_with(p.allowed_entity_types[1].as_str()));
    }

    #[test]
    fn an_override_outside_the_declared_prefixes_is_added() {
        let p = Profile::derive(
            &cfg(&[("a-f-G-U-C", "x:acme:infantry")]),
            &key().verifying_key(),
            &["mim:"],
        );
        assert!(p
            .allowed_entity_types
            .contains(&"x:acme:infantry".to_string()));
    }

    #[test]
    fn an_override_already_covered_by_a_prefix_is_not_duplicated() {
        let p = Profile::derive(
            &cfg(&[("a-f-A-M-F", "mim:aircraft")]),
            &key().verifying_key(),
            &["mim:"],
        );
        assert_eq!(p.allowed_entity_types, vec!["mim:"]);
    }

    #[test]
    fn the_contract_generation_is_declared() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]);
        assert_eq!(p.contract.as_deref(), Some("v1"));
    }

    #[test]
    fn the_advisory_ceiling_is_the_runtime_frame_cap() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]);
        assert_eq!(p.max_payload_bytes, Some(crate::MAX_FRAME_BYTES as u64));
    }

    /// The document is handed to an operator and compared against what they
    /// registered, so two runs of the same config must produce the same bytes.
    /// `entity_map` is a HashMap, whose iteration order differs run to run, so
    /// the appended overrides are sorted rather than emitted as encountered.
    #[test]
    fn the_same_config_always_produces_the_same_bytes() {
        let c = cfg(&[
            ("a-f-G-U-C", "x:acme:infantry"),
            ("a-f-A-M-F", "x:acme:aircraft"),
            ("a-h-S-X-M", "x:zulu:vessel"),
            ("a-n-G-U-C", "x:alpha:vehicle"),
            ("a-u-G-U-C", "mim:object"),
        ]);
        let first = Profile::derive(&c, &key().verifying_key(), &["mim:", "x:cot:"]).to_json();
        for _ in 0..64 {
            assert_eq!(
                Profile::derive(&c, &key().verifying_key(), &["mim:", "x:cot:"]).to_json(),
                first,
                "profile output varied between runs of the same config"
            );
        }
        // A fresh Config parsed from the same text must agree too, so the order
        // does not depend on how the map happened to be built.
        let rebuilt = cfg(&[
            ("a-u-G-U-C", "mim:object"),
            ("a-n-G-U-C", "x:alpha:vehicle"),
            ("a-h-S-X-M", "x:zulu:vessel"),
            ("a-f-A-M-F", "x:acme:aircraft"),
            ("a-f-G-U-C", "x:acme:infantry"),
        ]);
        assert_eq!(
            Profile::derive(&rebuilt, &key().verifying_key(), &["mim:", "x:cot:"]).to_json(),
            first,
            "profile output depended on insertion order rather than content"
        );
    }

    #[test]
    fn the_flag_is_matched_exactly() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(requested(&a(&["ajar-asterix", "--profile", "x.toml"])));
        assert!(requested(&a(&["ajar-asterix", "x.toml", "--profile"])));
        assert!(!requested(&a(&["ajar-asterix", "x.toml"])));
        assert!(!requested(&a(&["ajar-asterix", "--profiles"])));
    }
}
