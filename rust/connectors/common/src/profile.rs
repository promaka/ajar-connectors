// SPDX-License-Identifier: Apache-2.0
//! The connector profile the operator registers, derived from the loaded config
//! and the signing key. `allowed_entity_types` are prefixes, matched by Core with
//! `starts_with`, so an open-ended fallback such as `x:cot:` is expressible.
//! Rate limits are the operator's policy and are never emitted.

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::config::Config;

/// The profile document, matching Core's `ConnectorSpec` schema.
#[derive(Debug, Serialize, PartialEq)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    pub source_id: String,
    pub allowed_entity_types: Vec<String>,
    /// Advisory: the runtime's frame cap. Core enforces its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    pub verifying_key_hex: String,
}

impl Profile {
    pub fn derive(
        cfg: &Config,
        verifying_key: &VerifyingKey,
        entity_type_prefixes: &[&str],
    ) -> Self {
        // An entity_map override can name a type outside the connector's own
        // prefixes; Core would refuse it unless listed. Sorted, since the map's
        // order varies and the operator compares this against the registration.
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

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("profile is plain data")
    }
}

/// Whether the arguments ask to print the profile instead of running.
pub fn requested(args: &[String]) -> bool {
    args.iter().any(|a| a == "--profile")
}

/// Load the config's key and emit the profile as JSON.
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
    fn key_is_the_public_half() {
        let k = key();
        let p = Profile::derive(&cfg(&[]), &k.verifying_key(), &["mim:"]);
        assert_eq!(
            p.verifying_key_hex,
            hex::encode(k.verifying_key().to_bytes())
        );
        assert_eq!(p.verifying_key_hex.len(), 64);
        assert!(
            !p.to_json().contains(&hex::encode(k.to_bytes())),
            "the private half must never appear"
        );
    }

    #[test]
    fn rate_limits_are_never_asserted() {
        let json = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]).to_json();
        assert!(!json.contains("rate_capacity"));
        assert!(!json.contains("rate_refill_per_sec"));
    }

    #[test]
    fn entity_types_are_prefixes() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:", "x:cot:"]);
        assert_eq!(p.allowed_entity_types, vec!["mim:", "x:cot:"]);
        assert!("x:cot:a-f-G-U-C-I".starts_with(p.allowed_entity_types[1].as_str()));
    }

    #[test]
    fn override_outside_the_prefixes_is_added() {
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
    fn override_covered_by_a_prefix_is_not_added() {
        let p = Profile::derive(
            &cfg(&[("a-f-A-M-F", "mim:aircraft")]),
            &key().verifying_key(),
            &["mim:"],
        );
        assert_eq!(p.allowed_entity_types, vec!["mim:"]);
    }

    #[test]
    fn contract_generation_is_declared() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]);
        assert_eq!(p.contract.as_deref(), Some("v1"));
    }

    #[test]
    fn advisory_ceiling_is_the_frame_cap() {
        let p = Profile::derive(&cfg(&[]), &key().verifying_key(), &["mim:"]);
        assert_eq!(p.max_payload_bytes, Some(crate::MAX_FRAME_BYTES as u64));
    }

    #[test]
    fn same_config_produces_the_same_bytes() {
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
    fn flag_is_matched_exactly() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(requested(&a(&["ajar-asterix", "--profile", "x.toml"])));
        assert!(requested(&a(&["ajar-asterix", "x.toml", "--profile"])));
        assert!(!requested(&a(&["ajar-asterix", "x.toml"])));
        assert!(!requested(&a(&["ajar-asterix", "--profiles"])));
    }
}
