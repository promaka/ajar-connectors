// SPDX-License-Identifier: Apache-2.0
//! The ajar-up gate: in-test signed packets, a real nats-server and the real binaries.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use ajar_connector::{EventBuilder, SigningKey};
use ed25519_dalek::Signer as _;
use futures_util::StreamExt as _;
use sha2::Digest as _;

const SIG_DOMAIN: &[u8] = b"ajar-onboard-manifest:1\n";
const EGRESS_SEED: [u8; 32] = [0x11; 32];
const SIGNING_SEED: [u8; 32] = [0x22; 32];

/// Kills and reaps the child on drop.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A nats-server on a free port, or `None` to skip outside CI.
async fn broker() -> Option<(KillOnDrop, u16)> {
    let bin = std::env::var("NATS_SERVER_BIN").unwrap_or_else(|_| "nats-server".into());
    let present = Command::new(&bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !present {
        assert!(
            std::env::var("CI").is_err(),
            "nats-server is required in CI: the up gate must run, not skip"
        );
        eprintln!("up gate SKIPPED: no nats-server binary");
        return None;
    }
    let port = free_port();
    let child = Command::new(&bin)
        .args(["-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let broker = KillOnDrop(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "nats-server did not come up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Some((broker, port))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn egress_key() -> SigningKey {
    SigningKey::from_bytes(&EGRESS_SEED)
}

/// A signed packet tar of `manifest` plus `extra` files, all pinned in
/// `files[]`.
fn build_packet(dir: &Path, manifest: &serde_json::Value, extra: &[(&str, &[u8])]) -> PathBuf {
    let egress = egress_key();
    let mut manifest = manifest.clone();
    let pub_hex = hex::encode(egress.verifying_key().to_bytes());
    let mut files = vec![serde_json::json!({
        "path": "egress.pub",
        "sha256": hex::encode(sha2::Sha256::digest(pub_hex.as_bytes())),
    })];
    for (name, bytes) in extra {
        files.push(serde_json::json!({
            "path": name,
            "sha256": hex::encode(sha2::Sha256::digest(bytes)),
        }));
    }
    manifest["files"] = serde_json::Value::Array(files);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&manifest_bytes);
    let sig_hex = hex::encode(egress.sign(&msg).to_bytes());

    let tar_path = dir.join("packet.tar");
    let mut b = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
    let mut add = |name: &str, data: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    };
    add("manifest.json", &manifest_bytes);
    add("manifest.sig", sig_hex.as_bytes());
    add("egress.pub", pub_hex.as_bytes());
    for (name, bytes) in extra {
        add(name, bytes);
    }
    b.into_inner().unwrap();
    tar_path
}

fn consumer_manifest(nats_url: &str, subject: &str, formats: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "manifest_version": "1",
        "role": "consumer",
        "source_id": "ops-c2",
        "nats_url": nats_url,
        "egress_subject": subject,
        "formats": formats,
        "egress_verifying_key_hex": hex::encode(egress_key().verifying_key().to_bytes()),
        "keys": {},
    })
}

fn ajar_up(tar: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ajar-up"));
    cmd.arg(tar).args(args);
    cmd
}

fn run_ajar_up(tar: &Path, args: &[&str]) -> Output {
    ajar_up(tar, args).output().unwrap()
}

fn workspace_bin(name: &str) -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let p = workspace.join("target/debug").join(name);
    if !p.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", name])
            .current_dir(workspace)
            .status()
            .unwrap();
        assert!(status.success(), "building {name}");
    }
    p
}

fn path_arg(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn producer_packet_runs_connector_to_governed_event() {
    let Some((_broker, nats_port)) = broker().await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let udp_port = free_port();
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "source_id": "up-gate-1",
        "protocol": "ais-nmea",
        "nats_url": format!("nats://127.0.0.1:{nats_port}"),
        "subject": "ajar.ingest.up-gate-1",
        "transport": { "kind": "udp", "bind": format!("127.0.0.1:{udp_port}") },
        "keys": { "signing_key_path": "up-gate-1.signing.key" },
    });
    // Mint flow: the seed rides in the tar.
    let tar = build_packet(
        dir.path(),
        &manifest,
        &[("up-gate-1.signing.key", &SIGNING_SEED)],
    );

    let unpacked = dir.path().join("unpacked");
    let out = run_ajar_up(
        &tar,
        &[
            "--dir",
            path_arg(&unpacked),
            "--no-exec",
            "--timeout-secs",
            "3",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "ajar-up failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("packet verified"), "{stdout}");
    assert!(
        stdout.contains("Everything the doctor can check"),
        "{stdout}"
    );
    assert!(stdout.contains("ready to run:"), "{stdout}");
    let run_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('/') && l.contains("ajar-ais-nmea"))
        .unwrap_or_else(|| panic!("no run line in:\n{stdout}"))
        .trim();
    let config_path = run_line.split_whitespace().last().unwrap().to_string();

    let nc = async_nats::connect(format!("nats://127.0.0.1:{nats_port}"))
        .await
        .unwrap();
    let mut sub = nc
        .subscribe("ajar.ingest.up-gate-1".to_string())
        .await
        .unwrap();

    let _connector = KillOnDrop(
        Command::new(workspace_bin("ajar-ais-nmea"))
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(800)).await;

    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let sentence = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23";
    for _ in 0..20 {
        sock.send_to(sentence, ("127.0.0.1", udp_port)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(200), sub.next()).await {
            let key = SigningKey::from_bytes(&SIGNING_SEED);
            let canonical = ajar_connector::verify(&msg.payload, &key.verifying_key())
                .expect("event verifies under the packet's seed");
            assert!(!canonical.is_empty());
            return;
        }
    }
    panic!("no governed event arrived from the packet-started connector");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumer_tap_passes_verified_and_rejects_tampered() {
    let Some((_broker, nats_port)) = broker().await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let subject = "ajar.egress.cot.up-gate";
    let manifest = consumer_manifest(&format!("nats://127.0.0.1:{nats_port}"), subject, &["cot"]);
    let tar = build_packet(dir.path(), &manifest, &[]);

    let mut child = ajar_up(&tar, &["--dir", path_arg(&dir.path().join("unpacked"))])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();
    let _child = KillOnDrop(child);

    let mut err_reader = BufReader::new(child_stderr);
    let mut line = String::new();
    err_reader.read_line(&mut line).unwrap();
    assert!(line.contains("verified tap"), "{line}");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let event = EventBuilder::new("radar-x", "mim:vessel")
        .new_id()
        .now()
        .payload(b"<event uid='tap-proof'/>".to_vec())
        .build()
        .unwrap();
    let sealed = ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &egress_key());
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    let nc = async_nats::connect(format!("nats://127.0.0.1:{nats_port}"))
        .await
        .unwrap();
    nc.publish(subject.to_string(), tampered.into())
        .await
        .unwrap();
    nc.publish(subject.to_string(), sealed.into())
        .await
        .unwrap();
    nc.flush().await.unwrap();

    // The tampered event went first, so the first stdout line proves it was
    // not handed over.
    let mut out_reader = BufReader::new(child_stdout);
    let mut payload_line = String::new();
    out_reader.read_line(&mut payload_line).unwrap();
    assert_eq!(payload_line.trim_end(), "<event uid='tap-proof'/>");

    let mut rejected_seen = false;
    for _ in 0..5 {
        let mut l = String::new();
        if err_reader.read_line(&mut l).unwrap() == 0 {
            break;
        }
        if l.contains("rejected") {
            rejected_seen = true;
            break;
        }
    }
    assert!(
        rejected_seen,
        "the tampered event must be reported on stderr"
    );
}

#[test]
fn to_tak_needs_the_cot_format() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = consumer_manifest("nats://127.0.0.1:1", "ajar.egress.>", &["geojson"]);
    let tar = build_packet(dir.path(), &manifest, &[]);

    let out = run_ajar_up(
        &tar,
        &[
            "--dir",
            path_arg(&dir.path().join("u")),
            "--to-tak",
            "tak.example:8089",
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--to-tak needs the cot format"), "{err}");
    assert!(err.contains("geojson"), "{err}");
}

#[test]
fn to_http_writes_config_for_listed_format() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = consumer_manifest("nats://127.0.0.1:1", "ajar.egress.>", &["geojson"]);
    let tar = build_packet(dir.path(), &manifest, &[]);
    let unpacked = dir.path().join("u");

    let out = run_ajar_up(
        &tar,
        &[
            "--dir",
            path_arg(&unpacked),
            "--to-http",
            "http://127.0.0.1:9/hook",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(unpacked.join("ops-c2-http-egress.toml")).unwrap();
    assert!(cfg.contains("ajar.egress.geojson.>"), "{cfg}");
}

#[test]
fn consumer_check_passes_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = consumer_manifest("nats://127.0.0.1:1", "ajar.egress.cot.check", &["cot"]);
    let tar = build_packet(dir.path(), &manifest, &[]);

    let out = run_ajar_up(&tar, &["--dir", path_arg(&dir.path().join("c")), "--check"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("check passed: consumer packet for ops-c2"),
        "{stdout}"
    );
    assert!(stdout.contains("consumer packet valid"), "{stdout}");
}

#[test]
fn consumer_check_refuses_undelivered_cert() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = consumer_manifest("nats://127.0.0.1:1", "ajar.egress.cot.check", &["cot"]);
    manifest["keys"] = serde_json::json!({ "ca_cert_path": "missing-ca.crt" });
    let tar = build_packet(dir.path(), &manifest, &[]);

    let out = run_ajar_up(&tar, &["--dir", path_arg(&dir.path().join("u")), "--check"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("did not deliver"), "{err}");
}

#[test]
fn tampered_packet_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "source_id": "t-1",
        "protocol": "ais-nmea",
        "nats_url": "nats://127.0.0.1:1",
        "transport": { "kind": "udp", "bind": "127.0.0.1:0" },
        "keys": { "signing_key_path": "t-1.signing.key" },
    });
    let tar = build_packet(dir.path(), &manifest, &[]);

    let mut bytes = std::fs::read(&tar).unwrap();
    let pos = bytes
        .windows(b"\"source_id\"".len())
        .position(|w| w == b"\"source_id\"")
        .unwrap();
    bytes[pos + 1] = b'X';
    let tampered = dir.path().join("tampered.tar");
    std::fs::write(&tampered, bytes).unwrap();

    let out = run_ajar_up(&tampered, &["--dir", path_arg(&dir.path().join("u"))]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("does not verify under the packet's egress key"),
        "{err}"
    );
}
