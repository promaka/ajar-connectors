// SPDX-License-Identifier: Apache-2.0
//! Generates Rust types from `event.proto` with prost-build and a vendored protoc.

use std::path::PathBuf;

fn main() {
    // The published crate has no vendor/ and builds from its copy in contract/,
    // which scripts/check-contract.sh keeps byte-identical.
    let repo = PathBuf::from("../../vendor/contract");
    let (proto, include) = if repo.join("event.proto").is_file() {
        (repo.join("event.proto"), repo)
    } else {
        (
            PathBuf::from("contract/event.proto"),
            PathBuf::from("contract"),
        )
    };

    println!("cargo:rerun-if-changed={}", proto.display());

    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
        std::env::set_var("PROTOC", protoc);
    }

    prost_build::Config::new()
        .compile_protos(&[proto], &[include])
        .expect("failed to compile vendored event.proto");
}
