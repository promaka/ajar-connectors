// SPDX-License-Identifier: Apache-2.0
//! `ajar-verify`: checks the Ed25519 seal on an Ajar event and prints what it
//! carries. Needs no connector, broker, Core or network. Exits 0 when the seal
//! verifies and 1 otherwise.

use std::io::Read;
use std::process::ExitCode;

use ajar_connector::event::Event;
use ajar_connector::VerifyingKey;
use anyhow::Context;
use prost::Message;

const USAGE: &str = "\
ajar-verify — check the seal on an Ajar event

USAGE:
    ajar-verify --key <HEX> [FILE]
    ajar-verify --key-file <PATH> [FILE]

The event is read from FILE, or from stdin when FILE is omitted.

OPTIONS:
    --key <HEX>         32-byte Ed25519 verifying key as 64 hex characters
    --key-file <PATH>   file holding the key as raw bytes or hex
    --quiet             verify only; print nothing on success
    --help              show this message

EXIT STATUS:
    0   the seal verified
    1   the seal did not verify, or the input could not be read
";

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            if let Some(text) = output {
                println!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ajar-verify: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<Option<String>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Some(USAGE.trim_end().to_string()));
    }

    let mut key_hex: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut input: Option<String> = None;
    let mut quiet = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_hex = Some(it.next().context("--key needs a value")?.clone()),
            "--key-file" => key_file = Some(it.next().context("--key-file needs a value")?.clone()),
            "--quiet" | "-q" => quiet = true,
            other if other.starts_with('-') => anyhow::bail!("unknown option {other}"),
            other => input = Some(other.to_string()),
        }
    }

    let key = match (key_hex, key_file) {
        (Some(hex), None) => parse_key(hex.trim().as_bytes())?,
        (None, Some(path)) => {
            let raw = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
            parse_key(&raw)?
        }
        (Some(_), Some(_)) => anyhow::bail!("use --key or --key-file, not both"),
        (None, None) => anyhow::bail!("a verifying key is required (--key or --key-file)"),
    };

    let sealed = match &input {
        Some(path) => std::fs::read(path).with_context(|| format!("reading {path}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };

    let canonical = ajar_connector::verify(&sealed, &key)?;
    if quiet {
        return Ok(None);
    }

    // Nothing is decoded until the seal has verified.
    let event = Event::decode(canonical)
        .context("seal verified, but the payload is not a canonical Ajar event")?;
    Ok(Some(describe(&event, sealed.len(), canonical.len())))
}

/// Accepts a key as 64 hex characters or 32 raw bytes, ignoring whitespace.
fn parse_key(raw: &[u8]) -> anyhow::Result<VerifyingKey> {
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut bytes = [0u8; 32];
    match trimmed.len() {
        64 => hex::decode_to_slice(&trimmed, &mut bytes).context("key is not valid hex")?,
        32 => bytes.copy_from_slice(&trimmed),
        n => anyhow::bail!("key must be 32 raw bytes or 64 hex characters, got {n} bytes"),
    }
    VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 verifying key")
}

/// Plain-text summary of a verified event, one field per line.
fn describe(event: &Event, sealed_len: usize, canonical_len: usize) -> String {
    let mut out = String::new();
    out.push_str("seal: VERIFIED\n");
    out.push_str(&format!(
        "bytes: {sealed_len} sealed ({canonical_len} canonical + 64 signature)\n"
    ));
    out.push_str(&format!("schema_version: {}\n", event.schema_version));
    out.push_str(&format!("id: {}\n", event.id));
    out.push_str(&format!("source_id: {}\n", event.source_id));
    out.push_str(&format!("entity_type: {}\n", event.entity_type));
    out.push_str(&format!("timestamp: {}\n", event.timestamp));
    if !event.received_at.is_empty() {
        out.push_str(&format!("received_at: {}\n", event.received_at));
    }
    if let Some(loc) = &event.location {
        out.push_str(&format!(
            "location: {:.6}, {:.6} @ {:.1} m\n",
            loc.latitude, loc.longitude, loc.altitude_m
        ));
    }
    if event.confidence != 0.0 {
        out.push_str(&format!("confidence: {}\n", event.confidence));
    }
    if !event.policy_tags.is_empty() {
        out.push_str(&format!("policy_tags: {}\n", event.policy_tags.join(", ")));
    }
    if !event.payload.is_empty() {
        out.push_str(&format!("payload: {} bytes\n", event.payload.len()));
    }
    for a in &event.attributes {
        out.push_str(&format!("attribute {}: {}\n", a.key, a.value));
    }
    for m in &event.metadata {
        out.push_str(&format!("metadata {}: {}\n", m.key, m.value));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hex_or_raw_key() {
        let raw = [0x47u8; 32];
        let as_hex = hex::encode(raw);
        assert!(parse_key(as_hex.as_bytes()).is_ok());
        assert!(parse_key(&raw).is_ok());
        assert!(
            parse_key(format!("{as_hex}\n").as_bytes()).is_ok(),
            "trailing newline"
        );
    }

    #[test]
    fn rejects_wrong_length_or_non_hex_key() {
        assert!(parse_key(b"deadbeef").is_err());
        assert!(parse_key(&[0u8; 31]).is_err());
        assert!(parse_key(&[b'z'; 64]).is_err());
    }

    #[test]
    fn describes_a_verified_event() {
        let event = Event {
            schema_version: "v1".into(),
            id: "0192f1f4-0000-7000-8000-000000000000".into(),
            source_id: "acme-radar-1".into(),
            entity_type: "mim:aircraft".into(),
            timestamp: "2026-06-10T08:00:00Z".into(),
            ..Default::default()
        };
        let text = describe(&event, 128, 64);
        assert!(text.starts_with("seal: VERIFIED"));
        assert!(text.contains("source_id: acme-radar-1"));
        assert!(text.contains("entity_type: mim:aircraft"));
    }
}
