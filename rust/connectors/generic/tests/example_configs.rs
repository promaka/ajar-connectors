// SPDX-License-Identifier: Apache-2.0
//! Every `*.example.toml` in the workspace parses, points its signing key at a
//! seed, and, for generic, passes the boot-time ontology gate.

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
const OWN_SCHEMA: &[&str] = &["sink", "tak-egress", "generic-egress", "sapient-egress"];

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

        // The .key PEM is the mTLS key; the signing key is the .seed.
        for line in text.lines() {
            if line.trim_start().starts_with("signing_key_path") {
                assert!(
                    !line.contains(".key\""),
                    "{name}: signing_key_path must reference the .seed, not the mTLS PEM: {line}"
                );
            }
        }

        if OWN_SCHEMA.contains(&crate_name) {
            text.parse::<toml::Table>()
                .unwrap_or_else(|e| panic!("{name}: not valid TOML: {e}"));
            continue;
        }

        let cfg: common::Config = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("{name}: does not parse as a connector config: {e}"));

        if crate_name == "generic" {
            let mapping = Mapping::load(path.to_str().unwrap())
                .unwrap_or_else(|e| panic!("{name}: mapping does not load: {e}"));
            let declared = common::ontology::Declared {
                entity_type: mapping.entity_type.clone(),
                attributes: mapping.attributes.values().cloned().collect(),
                fixed_values: cfg
                    .default_hostility
                    .clone()
                    .map(|v| vec![("hostility".to_string(), v)])
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
