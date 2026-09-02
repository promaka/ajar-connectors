// SPDX-License-Identifier: Apache-2.0
//! The ajar-up gate: real packets, a real broker, the real binaries.
//!
//! Producer: a signed packet tar built in-test goes through `ajar-up
//! --no-exec` (verify, place, configure, preflight, print the command), the
//! printed connector is then actually run, fed one AIS sentence over UDP,
//! and the event must arrive on the ingest subject verifying under the seed
//! the packet carried.
//!
//! Consumer: `ajar-up` runs as the verified tap; a Core-signed event's
//! payload must reach stdout, and a tampered one must be rejected, counted,
//! and never handed over.
//!
//! nats-server policy matches the other gates: required in CI, skip locally
//! when absent.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};
use ed25519_dalek::Signer as _;

const SIG_DOMAIN: &[u8] = b"ajar-onboard-manifest:1\n";

fn nats_server() -> Option<String> {
    let bin = std::env::var("NATS_SERVER_BIN").unwrap_or_else(|_| "nats-server".into());
    let ok = Command::new(&bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Some(bin)
    } else if std::env::var("CI").is_ok() {
        panic!("nats-server is required in CI: the up gate must run, not skip");
    } else {
        eprintln!("up gate SKIPPED: no nats-server binary");
        None
    }
}

struct Broker(Child);
impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_up(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "nats-server did not come up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    b
}

/// Build a signed packet tar: manifest.json + manifest.sig + egress.pub +
/// any extra files (name, bytes, listed-in-files[]).
fn build_packet(
    dir: &std::path::Path,
    egress: &SigningKey,
    manifest_json: &serde_json::Value,
    extra: &[(&str, &[u8])],
) -> std::path::PathBuf {
    use sha2::Digest as _;
    let mut manifest = manifest_json.clone();
    // files[]: pin egress.pub and every listed extra.
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
    let file = std::fs::File::create(&tar_path).unwrap();
    let mut b = tar::Builder::new(file);
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

fn workspace_bin(name: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target/debug")
        .join(name);
    if !p.exists() {
        // Build it: the gate exercises the real binary, not a stand-in.
        let status = Command::new("cargo")
            .args([
                "build",
                "-p",
                &format!("ajar-{}", name.trim_start_matches("ajar-")),
            ])
            .current_dir(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap(),
            )
            .status()
            .unwrap();
        assert!(status.success(), "building {name}");
    }
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_packet_becomes_a_running_connector_and_a_governed_event() {
    let Some(nats_bin) = nats_server() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("ajar-up-prod-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let nats_port = free_port();
    let udp_port = free_port();
    let _broker = Broker(
        Command::new(&nats_bin)
            .args(["-p", &nats_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_up(nats_port).await;

    let egress = SigningKey::from_bytes(&rand32());
    let seed = rand32();
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "source_id": "up-gate-1",
        "protocol": "ais-nmea",
        "nats_url": format!("nats://127.0.0.1:{nats_port}"),
        "subject": "ajar.ingest.up-gate-1",
        "transport": { "kind": "udp", "bind": format!("127.0.0.1:{udp_port}") },
        "keys": { "signing_key_path": "up-gate-1.signing.key" },
    });
    // The mint flow: the seed rides in the tar, never in files[].
    let tar = build_packet(
        &dir,
        &egress,
        &manifest,
        &[("up-gate-1.signing.key", &seed)],
    );

    // ajar-up --no-exec: verify + place + configure + preflight + print.
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar)
        .args([
            "--dir",
            dir.join("unpacked").to_str().unwrap(),
            "--no-exec",
            "--timeout-secs",
            "3",
        ])
        .output()
        .unwrap();
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

    // Subscribe before the connector starts, then run the printed command
    // (with the real workspace binary) and feed it one AIS sentence.
    let nc = async_nats::connect(format!("nats://127.0.0.1:{nats_port}"))
        .await
        .unwrap();
    let mut sub = nc
        .subscribe("ajar.ingest.up-gate-1".to_string())
        .await
        .unwrap();

    let connector_bin = workspace_bin("ajar-ais-nmea");
    let _connector = ChildGuard(
        Command::new(&connector_bin)
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
        if let Ok(Some(msg)) = tokio::time::timeout(
            Duration::from_millis(200),
            futures_util::StreamExt::next(&mut sub),
        )
        .await
        {
            // The envelope verifies under the seed the packet carried: the
            // whole chain, packet to governed event.
            let key = SigningKey::from_bytes(&seed);
            let canonical = ajar_connector::verify(&msg.payload, &key.verifying_key())
                .expect("event verifies under the packet's seed");
            assert!(!canonical.is_empty());
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    }
    panic!("no governed event arrived from the packet-started connector");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumer_packet_taps_verified_events_and_refuses_tampered_ones() {
    let Some(nats_bin) = nats_server() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("ajar-up-cons-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let nats_port = free_port();
    let _broker = Broker(
        Command::new(&nats_bin)
            .args(["-p", &nats_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_up(nats_port).await;

    let egress = SigningKey::from_bytes(&rand32());
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "role": "consumer",
        "source_id": "ops-c2",
        "nats_url": format!("nats://127.0.0.1:{nats_port}"),
        "egress_subject": "ajar.egress.cot.up-gate",
        "formats": ["cot"],
        "egress_verifying_key_hex": hex::encode(egress.verifying_key().to_bytes()),
        "keys": {},
    });
    let tar = build_packet(&dir, &egress, &manifest, &[]);

    let mut child = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar)
        .args(["--dir", dir.join("unpacked").to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();
    let mut child = ChildGuard(child);

    // Wait for the tap to announce itself on stderr.
    let mut err_reader = BufReader::new(child_stderr);
    let mut line = String::new();
    err_reader.read_line(&mut line).unwrap();
    assert!(line.contains("verified tap"), "{line}");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A Core-signed event whose payload is a CoT snippet...
    let event = EventBuilder::new("radar-x", "mim:vessel")
        .new_id()
        .now()
        .payload(b"<event uid='tap-proof'/>".to_vec())
        .build()
        .unwrap();
    let sealed = seal(&canonical_bytes(&event), &egress);
    // ...and a tampered copy that must never reach stdout.
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    let nc = async_nats::connect(format!("nats://127.0.0.1:{nats_port}"))
        .await
        .unwrap();
    nc.publish("ajar.egress.cot.up-gate".to_string(), tampered.into())
        .await
        .unwrap();
    nc.publish("ajar.egress.cot.up-gate".to_string(), sealed.into())
        .await
        .unwrap();
    nc.flush().await.unwrap();

    // The valid payload arrives on stdout; reading it first proves ordering
    // did not sneak the tampered one through.
    let mut out_reader = BufReader::new(child_stdout);
    let mut payload_line = String::new();
    out_reader.read_line(&mut payload_line).unwrap();
    assert_eq!(payload_line.trim_end(), "<event uid='tap-proof'/>");

    // And the rejection is visible, counted, on stderr.
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
    assert!(rejected_seen, "the tampered event must be rejected loudly");

    let _ = child.0.kill();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_delivery_flag_must_name_a_format_the_deployment_egresses() {
    let dir = std::env::temp_dir().join(format!("ajar-up-fmt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let egress = SigningKey::from_bytes(&rand32());
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "role": "consumer",
        "source_id": "ops-c2",
        "nats_url": "nats://127.0.0.1:1",
        "egress_subject": "ajar.egress.>",
        "formats": ["geojson"],
        "egress_verifying_key_hex": hex::encode(egress.verifying_key().to_bytes()),
        "keys": {},
    });
    let tar = build_packet(&dir, &egress, &manifest, &[]);
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar)
        .args([
            "--dir",
            dir.join("u1").to_str().unwrap(),
            "--to-tak",
            "tak.example:8089",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--to-tak needs the cot format"), "{err}");
    assert!(err.contains("geojson"), "{err}");

    // The listed format works and the generated config subscribes its slug.
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar)
        .args([
            "--dir",
            dir.join("u2").to_str().unwrap(),
            "--to-http",
            "http://127.0.0.1:9/hook",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cfg = std::fs::read_to_string(dir.join("u2/ops-c2-http-egress.toml")).unwrap();
    assert!(cfg.contains("ajar.egress.geojson.>"), "{cfg}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_is_a_one_line_assertion_for_both_roles() {
    let dir = std::env::temp_dir().join(format!("ajar-up-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let egress = SigningKey::from_bytes(&rand32());

    // Consumer: --check exits 0 fast with the marker, touching no network.
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "role": "consumer",
        "source_id": "ops-c2",
        "nats_url": "nats://127.0.0.1:1",
        "egress_subject": "ajar.egress.cot.check",
        "formats": ["cot"],
        "egress_verifying_key_hex": hex::encode(egress.verifying_key().to_bytes()),
        "keys": {},
    });
    let tar = build_packet(&dir, &egress, &manifest, &[]);
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar)
        .args(["--dir", dir.join("c").to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("check passed: consumer packet for ops-c2"),
        "{stdout}"
    );
    assert!(stdout.contains("consumer packet valid"), "{stdout}");

    // A consumer manifest referencing an undelivered cert fails the check.
    let manifest_bad = serde_json::json!({
        "manifest_version": "1",
        "role": "consumer",
        "source_id": "ops-c2",
        "nats_url": "nats://127.0.0.1:1",
        "egress_subject": "ajar.egress.cot.check",
        "formats": ["cot"],
        "egress_verifying_key_hex": hex::encode(egress.verifying_key().to_bytes()),
        "keys": { "ca_cert_path": "missing-ca.crt" },
    });
    let dir2 = dir.join("bad");
    std::fs::create_dir_all(&dir2).unwrap();
    let tar2 = build_packet(&dir2, &egress, &manifest_bad, &[]);
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tar2)
        .args(["--dir", dir2.join("u").to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("did not deliver"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_tampered_packet_is_refused_before_anything_is_trusted() {
    let dir = std::env::temp_dir().join(format!("ajar-up-tamper-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let egress = SigningKey::from_bytes(&rand32());
    let manifest = serde_json::json!({
        "manifest_version": "1",
        "source_id": "t-1",
        "protocol": "ais-nmea",
        "nats_url": "nats://127.0.0.1:1",
        "transport": { "kind": "udp", "bind": "127.0.0.1:0" },
        "keys": { "signing_key_path": "t-1.signing.key" },
    });
    let tar = build_packet(&dir, &egress, &manifest, &[]);

    // Flip one byte inside the tar'd manifest: the signature must refuse it.
    let mut bytes = std::fs::read(&tar).unwrap();
    let pos = bytes
        .windows(b"\"source_id\"".len())
        .position(|w| w == b"\"source_id\"")
        .unwrap();
    bytes[pos + 1] = b'X';
    let tampered = dir.join("tampered.tar");
    std::fs::write(&tampered, bytes).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ajar-up"))
        .arg(&tampered)
        .args(["--dir", dir.join("u").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("does not verify under the packet's egress key"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
