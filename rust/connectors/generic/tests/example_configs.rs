// SPDX-License-Identifier: Apache-2.0
//! Every shipped example config must WORK when copied verbatim - an example
//! is copied by definition, so it is the worst place for a value that does
//! not parse, a key path the loader rejects, or a mapping the ontology would
//! quarantine. This gate walks every *.example.toml in the workspace:
//!
//!  - configs on the shared schema must parse strictly (deny_unknown_fields
//!    turns doc drift into a red build);
//!  - signing_key_path must not point at a .key PEM (the loader takes the
//!    32-byte .seed; the PEM is the mTLS key, a different key entirely);
//!  - generic mappings must pass the same ontology gate the connector
//!    enforces at boot, so a copied config cannot ship events Core discards.

use ajar_connector_common as common;
use ajar_generic::Mapping;

fn workspace_examples() -> Vec<std::path::PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("connectors workspace root")
        .to_path_buf();
    let mut found = Vec::new();
    for crate_dir in std::fs::read_dir(&root)
        .expect("workspace listing")
        .flatten()
    {
        if !crate_dir.path().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(crate_dir.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            let p = f.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".example.toml"))
            {
                found.push(p);
            }
        }
    }
    found.sort();
    assert!(found.len() >= 12, "example sweep found {}", found.len());
    found
}

/// Crates whose example uses their own config schema, not the shared one.
const OWN_SCHEMA: &[&str] = &["sink", "tak-egress", "generic-egress"];

#[test]
fn every_example_config_works_when_copied_verbatim() {
    for path in workspace_examples() {
        let name = path.file_name().unwrap().to_str().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let crate_name = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();

        // No example may point the signing seed at a PEM. (An mTLS tls_key
        // is a different key and legitimately a .key file.)
        for line in text.lines() {
            if line.trim_start().starts_with("signing_key_path") {
                assert!(
                    !line.contains(".key\""),
                    "{name}: signing_key_path must reference the .seed, not the mTLS PEM: {line}"
                );
            }
        }

        if OWN_SCHEMA.contains(&crate_name) {
            // Own schema: at minimum the TOML must parse.
            text.parse::<toml::Table>()
                .unwrap_or_else(|e| panic!("{name}: not valid TOML: {e}"));
            continue;
        }

        let cfg: common::Config = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("{name}: does not parse as a connector config: {e}"));

        // Generic mappings get the exact boot-time ontology gate.
        if crate_name == "generic" {
            let mapping = Mapping::load(path.to_str().unwrap())
                .unwrap_or_else(|e| panic!("{name}: mapping does not load: {e}"));
            let declared = common::ontology::Declared {
                entity_types: vec![mapping.entity_type.clone()],
                attributes: mapping.attributes.values().cloned().collect(),
                fixed_values: cfg
                    .default_hostility
                    .clone()
                    .map(|v| [("hostility".to_string(), v)].into_iter().collect())
                    .unwrap_or_default(),
            };
            let faults = common::ontology::check(&declared);
            assert!(
                faults.is_empty(),
                "{name}: the ontology would quarantine this mapping: {faults:?}"
            );
        }
    }
}
