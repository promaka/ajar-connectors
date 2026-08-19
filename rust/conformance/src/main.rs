// SPDX-License-Identifier: Apache-2.0
//! `ajar-conformance` — prove an implementation produces the bytes Ajar accepts.
//!
//! Any implementation, in any language, written by anyone. It runs offline, needs
//! no credentials, and never contacts Ajar Core: the vendored golden vectors are
//! the whole specification, so a partner can gate their own CI on this and stop
//! asking us whether their output is right.
//!
//! ## What your implementation must do
//!
//! It is invoked once per fixture, in two modes, with the fixture JSON on stdin
//! and **raw bytes** on stdout:
//!
//! ```text
//! <impl> canonical  < fixture.json  > canonical bytes
//! <impl> sealed     < fixture.json  > 64-byte signature ++ canonical bytes
//! ```
//!
//! For `sealed`, the 32-byte TEST signing seed is passed as hex in the
//! `AJAR_TEST_SIGNING_SEED` environment variable. It is a published test key and
//! must never be a production one.
//!
//! Anything written to stderr is captured and shown on failure; only stdout is
//! hashed. A non-zero exit, a timeout, or a hash mismatch fails that fixture.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use conformance::{contract_dir, load_vectors};
use sha2::{Digest, Sha256};

/// Modes an implementation is asked for, and the vector field each is checked
/// against.
const MODES: [&str; 2] = ["canonical", "sealed"];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug)]
struct Outcome {
    fixture: String,
    mode: &'static str,
    expected: String,
    actual: Option<String>,
    detail: Option<String>,
}

impl Outcome {
    fn passed(&self) -> bool {
        self.actual.as_deref() == Some(self.expected.as_str())
    }
}

/// Run one fixture through the implementation in one mode.
fn run_one(
    impl_cmd: &[String],
    fixture: &str,
    body: &str,
    mode: &'static str,
    seed: &str,
) -> (Option<String>, Option<String>) {
    let mut cmd = Command::new(&impl_cmd[0]);
    cmd.args(&impl_cmd[1..])
        .arg(mode)
        .env("AJAR_TEST_SIGNING_SEED", seed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (None, Some(format!("could not run implementation: {e}"))),
    };
    if let Some(mut stdin) = child.stdin.take() {
        // A closed pipe means the implementation exited early; the status below
        // reports why, so the write error itself is not the interesting failure.
        let _ = stdin.write_all(body.as_bytes());
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return (None, Some(format!("implementation failed: {e}"))),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let trimmed: String = err.lines().take(5).collect::<Vec<_>>().join("\n");
        return (
            None,
            Some(format!(
                "{fixture}/{mode}: implementation exited {}{}",
                out.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
                if trimmed.is_empty() {
                    String::new()
                } else {
                    format!("\n{trimmed}")
                }
            )),
        );
    }
    if out.stdout.is_empty() {
        return (
            None,
            Some(format!(
                "{fixture}/{mode}: implementation wrote no bytes to stdout"
            )),
        );
    }
    (Some(sha256_hex(&out.stdout)), None)
}

fn usage() -> ! {
    eprintln!(
        "ajar-conformance — prove an implementation produces the bytes Ajar accepts\n\
         \n\
         USAGE:\n\
         \x20   ajar-conformance run --impl <command> [args...] [--report <path>]\n\
         \n\
         The command is invoked once per fixture as `<command> [args...] <mode>`,\n\
         with the fixture JSON on stdin and raw bytes on stdout. Modes are\n\
         `canonical` and `sealed`; for `sealed` the TEST seed arrives as hex in\n\
         AJAR_TEST_SIGNING_SEED.\n\
         \n\
         Exits 0 if every vector matches, 1 otherwise. Runs offline."
    );
    std::process::exit(2)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 || argv[1] != "run" {
        usage();
    }
    let mut impl_cmd: Vec<String> = Vec::new();
    let mut report: Option<PathBuf> = None;
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--impl" => {
                i += 1;
                // Everything up to the next recognised flag belongs to the
                // implementation, so `--impl python3 adapter.py` works unquoted.
                while i < argv.len() && argv[i] != "--report" {
                    impl_cmd.push(argv[i].clone());
                    i += 1;
                }
            }
            "--report" => {
                i += 1;
                report = argv.get(i).map(PathBuf::from);
                i += 1;
            }
            _ => usage(),
        }
    }
    if impl_cmd.is_empty() {
        usage();
    }

    let vectors = load_vectors();
    let corpus = contract_dir().join("corpus");
    let mut outcomes: Vec<Outcome> = Vec::new();

    for (fixture, expected) in &vectors.vectors {
        let body = match std::fs::read_to_string(corpus.join(format!("{fixture}.json"))) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cannot read fixture {fixture}: {e}");
                std::process::exit(2);
            }
        };
        for mode in MODES {
            let want = match mode {
                "canonical" => expected.canonical_sha256.clone(),
                _ => expected.sealed_sha256.clone(),
            };
            let (actual, detail) =
                run_one(&impl_cmd, fixture, &body, mode, &vectors.signing_seed_hex);
            outcomes.push(Outcome {
                fixture: fixture.clone(),
                mode,
                expected: want,
                actual,
                detail,
            });
        }
    }

    let failed: Vec<&Outcome> = outcomes.iter().filter(|o| !o.passed()).collect();
    for o in &outcomes {
        let mark = if o.passed() { "ok  " } else { "FAIL" };
        println!("{mark} {}/{}", o.fixture, o.mode);
        if !o.passed() {
            if let Some(d) = &o.detail {
                println!("       {d}");
            } else {
                println!("       expected {}", o.expected);
                println!(
                    "       actual   {}",
                    o.actual.clone().unwrap_or_else(|| "<none>".into())
                );
            }
        }
    }

    if let Some(path) = report {
        let json = format!(
            "{{\n  \"contract\": \"v1\",\n  \"total\": {},\n  \"passed\": {},\n  \"failed\": {},\n  \"results\": [\n{}\n  ]\n}}\n",
            outcomes.len(),
            outcomes.len() - failed.len(),
            failed.len(),
            outcomes
                .iter()
                .map(|o| format!(
                    "    {{ \"fixture\": \"{}\", \"mode\": \"{}\", \"pass\": {}, \"expected\": \"{}\", \"actual\": {} }}",
                    o.fixture,
                    o.mode,
                    o.passed(),
                    o.expected,
                    o.actual.as_ref().map(|a| format!("\"{a}\"")).unwrap_or_else(|| "null".into())
                ))
                .collect::<Vec<_>>()
                .join(",\n")
        );
        if let Err(e) = std::fs::write(&path, json) {
            eprintln!("could not write report to {}: {e}", path.display());
            std::process::exit(2);
        }
    }

    if failed.is_empty() {
        println!("\nConformant — contract-v1 ({} vectors)", outcomes.len());
        std::process::exit(0);
    }
    println!(
        "\nNOT conformant — contract-v1 ({} of {} vectors failed)",
        failed.len(),
        outcomes.len()
    );
    std::process::exit(1);
}
