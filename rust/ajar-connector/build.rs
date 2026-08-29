// SPDX-License-Identifier: Apache-2.0
//! Generates Rust types from the vendored Ajar event contract.
//!
//! The proto in `vendor/contract/event.proto` is the single source of truth for
//! the cross-language wire format. We compile it with `prost-build`, using a
//! vendored `protoc` binary so a fresh `cargo build` needs no system protoc.

use std::path::PathBuf;

fn main() {
    // In the repository the contract lives at vendor/contract, the single
    // source of truth shared by every SDK; the published crate carries its own
    // copy under contract/, held byte-identical by scripts/check-contract.sh.
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

    // Use the bundled protoc unless the caller pins their own.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
        std::env::set_var("PROTOC", protoc);
    }

    prost_build::Config::new()
        .compile_protos(&[proto], &[include])
        .expect("failed to compile vendored event.proto");
}
