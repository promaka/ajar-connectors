// SPDX-License-Identifier: Apache-2.0
//! `ajar-conformance`: runs an implementation in any language against the golden
//! vectors, offline. The implementation is invoked as `<impl> canonical` and
//! `<impl> sealed` per fixture, with the fixture JSON on stdin and raw bytes on
//! stdout; for `sealed` the test seed arrives as hex in `AJAR_TEST_SIGNING_SEED`.
//! Only stdout is hashed; stderr is shown on failure.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

const MODES: [&str; 2] = ["canonical", "sealed"];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug)]
struct Outcome {
    fixture: String,
    mode: &'static str,
    expected: String,
    /// SHA-256 of the implementation's stdout, or why there is none.
    actual: Result<String, String>,
}

impl Outcome {
    fn passed(&self) -> bool {
        self.actual.as_ref() == Ok(&self.expected)
    }
}

/// Runs one fixture through the implementation in one mode.
fn run_one(
    impl_cmd: &[String],
    fixture: &str,
    body: &str,
    mode: &'static str,
    seed: &str,
) -> Result<String, String> {
    let mut cmd = Command::new(&impl_cmd[0]);
    cmd.args(&impl_cmd[1..])
        .arg(mode)
        .env("AJAR_TEST_SIGNING_SEED", seed)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not run implementation: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A closed pipe means the implementation exited early; the exit status
        // below reports why.
        let _ = stdin.write_all(body.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("implementation failed: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let trimmed: String = err.lines().take(5).collect::<Vec<_>>().join("\n");
        return Err(format!(
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
        ));
    }
    if out.stdout.is_empty() {
        return Err(format!(
            "{fixture}/{mode}: implementation wrote no bytes to stdout"
        ));
    }
    Ok(sha256_hex(&out.stdout))
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

    let vectors = conformance::load_vectors();
    let corpus = conformance::contract_dir().join("corpus");
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
            outcomes.push(Outcome {
                fixture: fixture.clone(),
                mode,
                expected: want,
                actual: run_one(&impl_cmd, fixture, &body, mode, &vectors.signing_seed_hex),
            });
        }
    }

    let failed: Vec<&Outcome> = outcomes.iter().filter(|o| !o.passed()).collect();
    for o in &outcomes {
        let mark = if o.passed() { "ok  " } else { "FAIL" };
        println!("{mark} {}/{}", o.fixture, o.mode);
        match &o.actual {
            _ if o.passed() => {}
            Err(detail) => println!("       {detail}"),
            Ok(actual) => {
                println!("       expected {}", o.expected);
                println!("       actual   {actual}");
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
                    o.actual.as_ref().map(|a| format!("\"{a}\"")).unwrap_or_else(|_| "null".into())
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
