// SPDX-License-Identifier: Apache-2.0
//! Compiles the vendored BSI Flex 335 schema (`proto/`, Crown copyright,
//! Apache-2.0) to Rust with prost, using the vendored protoc so a fresh build
//! needs no system protoc. The v2.0 schema is always compiled; v1.0 joins it
//! behind the `v1` feature.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");
    println!("cargo:rerun-if-changed={}", root.display());

    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
        std::env::set_var("PROTOC", protoc);
    }
    let well_known = protoc_bin_vendored::include_path().expect("vendored protoc includes");

    let mut entry_points = vec![root.join("sapient_msg/bsi_flex_335_v2_0/sapient_message.proto")];
    if std::env::var_os("CARGO_FEATURE_V1").is_some() {
        entry_points.push(root.join("sapient_msg/bsi_flex_335_v1_0/sapient_message.proto"));
    }

    prost_build::Config::new()
        .compile_protos(&entry_points, &[root, well_known])
        .expect("failed to compile the vendored BSI Flex 335 schema");
}
