// SPDX-License-Identifier: Apache-2.0
//! Generates Rust types from the vendored Ajar event contract.
//!
//! The proto in `vendor/contract/event.proto` is the single source of truth for
//! the cross-language wire format. We compile it with `prost-build`, using a
//! vendored `protoc` binary so a fresh `cargo build` needs no system protoc.

use std::path::PathBuf;

fn main() {
    let proto = PathBuf::from("../../vendor/contract/event.proto");
    let include = PathBuf::from("../../vendor/contract");

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
