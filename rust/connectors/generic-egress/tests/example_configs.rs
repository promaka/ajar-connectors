// SPDX-License-Identifier: Apache-2.0
//! Every `*.example.toml` of this connector loads and compiles its mapping or template.

#[test]
fn every_example_loads() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut loaded = 0;
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".example.toml") {
            continue;
        }
        ajar_generic_egress::config::load(path.to_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e:#}"));
        loaded += 1;
    }
    assert!(loaded >= 2, "found {loaded} examples");
}
