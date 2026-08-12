// SPDX-License-Identifier: Apache-2.0
//! `ajar-verify` — check the seal on an Ajar event and print what it carries.
//!
//! An Ajar event is a detached Ed25519 signature followed by canonically-encoded
//! protobuf. Verifying it establishes two things: that the bytes were sealed by
//! the holder of a particular key, and that nothing has altered them since. That
//! is the whole trust model, and this tool exercises it with nothing else
//! present — no connector, no broker, no Ajar Core, no network.
//!
//! A recipient of Ajar data can therefore confirm provenance for themselves
//! rather than taking the sender's word for it, which is the point of signing the
//! events in the first place.
//!
//! ```text
//! ajar-verify --key <64-hex-chars> event.sealed
//! ajar-verify --key-file publisher.pub < event.sealed
//! ```
//!
//! Exit status is 0 when the seal verifies and 1 when it does not, so it drops
//! into a pipeline or a CI check unchanged.

use std::io::Read;
use std::process::ExitCode;

use ajar_connector::{event::Event, verify};
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
        Err(message) => {
            eprintln!("ajar-verify: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Option<String>, String> {
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
            "--key" => key_hex = Some(it.next().ok_or("--key needs a value")?.clone()),
            "--key-file" => key_file = Some(it.next().ok_or("--key-file needs a value")?.clone()),
            "--quiet" | "-q" => quiet = true,
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            other => input = Some(other.to_string()),
        }
    }

    let key = match (key_hex, key_file) {
        (Some(hex), None) => parse_key(hex.trim().as_bytes())?,
        (None, Some(path)) => {
            let raw = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
            parse_key(&raw)?
        }
        (Some(_), Some(_)) => return Err("use --key or --key-file, not both".into()),
        (None, None) => return Err("a verifying key is required (--key or --key-file)".into()),
    };

    let sealed = match &input {
        Some(path) => std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            buf
        }
    };

    let canonical = verify(&sealed, &key).map_err(|e| e.to_string())?;
    if quiet {
        return Ok(None);
    }

    // Decoding is deliberately after verification: nothing is parsed until the
    // bytes have been shown to be authentic.
    let event = Event::decode(canonical).map_err(|e| {
        format!("seal verified, but the payload is not a canonical Ajar event: {e}")
    })?;
    Ok(Some(describe(&event, sealed.len(), canonical.len())))
}

/// Accept a key as 64 hex characters or as 32 raw bytes, so both `ajar keygen`
/// output and a raw key file work without conversion.
fn parse_key(raw: &[u8]) -> Result<ajar_connector::VerifyingKey, String> {
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let bytes: [u8; 32] = if trimmed.len() == 64 {
        let decoded = hex::decode(&trimmed).map_err(|e| format!("key is not valid hex: {e}"))?;
        decoded
            .try_into()
            .map_err(|_| "hex key must decode to 32 bytes".to_string())?
    } else if trimmed.len() == 32 {
        trimmed
            .try_into()
            .map_err(|_| "raw key must be 32 bytes".to_string())?
    } else {
        return Err(format!(
            "key must be 32 raw bytes or 64 hex characters, got {} bytes",
            trimmed.len()
        ));
    };
    ajar_connector::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("not a valid Ed25519 verifying key: {e}"))
}

/// A human-readable summary of a verified event. Deliberately plain text so it
/// greps and diffs; the canonical bytes remain the authority.
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
    fn accepts_a_key_as_hex_or_raw_bytes() {
        let raw = [0x47u8; 32];
        let as_hex = hex::encode(raw);
        assert!(parse_key(as_hex.as_bytes()).is_ok());
        assert!(parse_key(&raw).is_ok());
        // Trailing newline from a key file is tolerated.
        assert!(parse_key(format!("{as_hex}\n").as_bytes()).is_ok());
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length_or_alphabet() {
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
