// SPDX-License-Identifier: Apache-2.0
//! Runs the binary without a seed: a dry run exits 0, a publishing run is refused before any NATS connect.

use std::process::{Command, Output};

fn run_without_seed(flag: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_synthetic-radar"))
        .args([flag, "--ticks", "1"])
        .env_remove("AJAR_SIGNING_SEED")
        .env_remove("AJAR_HEALTH_ADDR")
        .output()
        .expect("run synthetic-radar")
}

#[test]
fn only_the_exact_flag_means_dry_run() {
    let exact = run_without_seed("--dry-run");
    assert!(
        exact.status.success(),
        "--dry-run must run without a seed: {}",
        String::from_utf8_lossy(&exact.stderr)
    );

    for near in [
        "--dry_run",
        "--dryrun",
        "-dry-run",
        "--DRY-RUN",
        "--dry-run=true",
    ] {
        let out = run_without_seed(near);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("set AJAR_SIGNING_SEED"),
            "{near} must not enable dry-run: {stderr}"
        );
    }
}
