// SPDX-License-Identifier: Apache-2.0
//! CLI wrapper around the doctor library. Exit 0 when everything the doctor
//! can check from here is fine, 1 when at least one check failed, 2 on usage
//! errors, so it drops into scripts and support runbooks unchanged.

use std::time::Duration;

use ajar_doctor::{report, Options};

fn usage() -> ! {
    eprintln!(
        "usage: ajar-doctor <config.toml> [--sources-dir <dir>] [--timeout-secs <n>]\n\
         \n\
         Checks a connector's setup step by step (config, signing key, registration,\n\
         endpoint, TLS, clock) and says which onboarding step is broken and what to do.\n\
         Reads the same config and AJAR_TLS_* environment the connector itself uses.\n\
         Read-only on the wire: it never publishes an event.\n\
         \n\
         --sources-dir <dir>   a local sink's registered-keys directory, for a real\n\
         \x20                     registration check when the sink runs on a box you can see\n\
         --timeout-secs <n>    per network step (default 5)"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<String> = None;
    let mut sources_dir: Option<String> = None;
    let mut timeout_secs: u64 = 5;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--sources-dir" => match it.next() {
                Some(v) => sources_dir = Some(v),
                None => usage(),
            },
            "--timeout-secs" => match it.next().and_then(|v| v.parse().ok()) {
                Some(v) => timeout_secs = v,
                None => usage(),
            },
            "-h" | "--help" => usage(),
            other if config_path.is_none() && !other.starts_with('-') => {
                config_path = Some(other.to_string())
            }
            _ => usage(),
        }
    }
    let Some(config_path) = config_path else {
        usage()
    };

    let opts = Options {
        config_path,
        sources_dir,
        timeout: Duration::from_secs(timeout_secs),
    };

    println!(
        "ajar-doctor {} checking {}\n",
        env!("CARGO_PKG_VERSION"),
        opts.config_path
    );
    let findings = ajar_doctor::run(&opts).await;
    let (text, healthy) = report::render(&findings);
    print!("{text}");
    std::process::exit(if healthy { 0 } else { 1 });
}
