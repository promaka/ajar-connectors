#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scaffold a new ingress connector on the shared runtime. Writes
#   rust/connectors/<name>/            a crate named ajar-<name>: parser, wiring,
#                                      example config, README, tests
# and adds it to the connectors workspace. Everything but the parser is the same
# as every shipped connector: config, key, mTLS NATS, every transport, the
# seal-and-publish loop, store-and-forward, health, shutdown.
#
# After it runs, the one file to edit is rust/connectors/<name>/src/<name>.rs.
#
# Usage:  scripts/new-connector.sh <name>      e.g. scripts/new-connector.sh acme-legacy
#         <name> is lower-case letters, digits and hyphens, and must be new.
set -euo pipefail

name="${1:-}"
if [[ -z "$name" ]]; then
  echo "usage: scripts/new-connector.sh <name>   (lower-case letters, digits, hyphens)" >&2
  exit 2
fi
if [[ ! "$name" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ ]]; then
  echo "error: '$name' must be lower-case letters, digits and hyphens, starting with a letter" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ws="$root/rust/connectors"
dir="$ws/$name"
if [[ -e "$dir" ]]; then
  echo "error: $dir already exists" >&2
  exit 1
fi
if grep -q "\"$name\"" "$ws/Cargo.toml"; then
  echo "error: \"$name\" is already a workspace member in rust/connectors/Cargo.toml" >&2
  exit 1
fi

crate="ajar-$name"
snake="${name//-/_}"
# PascalCase for the parser type: acme-legacy -> AcmeLegacy
pascal="$(echo "$name" | awk -F- '{ for (i = 1; i <= NF; i++) printf "%s%s", toupper(substr($i, 1, 1)), substr($i, 2) }')"

mkdir -p "$dir/src"

cat > "$dir/Cargo.toml" <<EOF
# SPDX-License-Identifier: Apache-2.0
[package]
name = "$crate"
description = "Ajar ingress connector for <your format>."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
publish = false

[[bin]]
name = "$crate"
path = "src/main.rs"

[features]
# DDS is compiled in so the shipped binary can read a topic on a ship's or a
# ROS 2 platform's bus; it is inert unless a config says kind = "dds".
default = ["dds"]
dds = ["ajar-connector-common/dds"]

[dependencies]
ajar-connector.workspace = true
ajar-connector-common.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
anyhow.workspace = true
EOF

cat > "$dir/src/lib.rs" <<EOF
// SPDX-License-Identifier: Apache-2.0
//! <Your format> ingress for Ajar.
//!
//! The connector is [\`${pascal}Parser\`], plugged into the shared
//! [\`ajar_connector_common\`] runtime. See \`src/main.rs\` for the wiring and
//! the repository's \`AGENTS.md\` for the rules every parser follows.

pub mod $snake;

pub use $snake::{${pascal}Error, ${pascal}Parser};
EOF

cat > "$dir/src/$snake.rs" <<EOF
// SPDX-License-Identifier: Apache-2.0
//! The parser: one native frame in, zero or more canonical events out.
//!
//! This file is the only format-specific code in the connector. As generated it
//! reads a text frame of the form \`lat,lon[,alt_m]\` so the crate builds, runs
//! and passes its tests before you touch it. Replace [\`${pascal}Parser::decode\`]
//! and the tests with your format, and keep the rules the tests pin down:
//!
//! - the raw frame is sealed verbatim in \`payload\`, nothing is dropped;
//! - every decoded field becomes an attribute in canonical units, with the
//!   native value kept in metadata;
//! - the feed's own identifier becomes the \`source_uid\` metadata key, so each
//!   platform stays its own track;
//! - malformed, truncated or hostile input is a typed error, never a panic.

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use std::fmt;

/// Every way a frame can be refused. Each variant is a reason the operator can
/// read in the log; none of them is a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ${pascal}Error {
    /// The frame is empty or whitespace.
    Empty,
    /// The frame is not UTF-8 text.
    NotText,
    /// The frame does not have the fields the format requires.
    Fields(usize),
    /// A field is not a number.
    Number(String),
    /// A coordinate is off the globe.
    Range(String),
    /// The SDK refused the event (the shape is invalid).
    Build(String),
}

impl fmt::Display for ${pascal}Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame"),
            Self::NotText => write!(f, "frame is not UTF-8 text"),
            Self::Fields(n) => write!(f, "expected lat,lon[,alt_m], got {n} field(s)"),
            Self::Number(s) => write!(f, "not a number: {s:?}"),
            Self::Range(s) => write!(f, "out of range: {s}"),
            Self::Build(e) => write!(f, "event rejected by the SDK: {e}"),
        }
    }
}

impl std::error::Error for ${pascal}Error {}

/// One decoded record. Add the fields your format carries.
#[derive(Debug, Clone, PartialEq)]
pub struct ${pascal}Record {
    pub lat: f64,
    pub lon: f64,
    pub alt_m: Option<f64>,
}

/// The connector: holds its Ajar identity and the operator's enrichment choices,
/// and turns frames into signed-ready events.
pub struct ${pascal}Parser {
    source_id: String,
    enrichment: Enrichment,
}

impl ${pascal}Parser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
        }
    }

    /// Decode one frame. Replace this with your format. Bounds-check every
    /// read; return an error for anything you do not understand.
    pub fn decode(&self, frame: &[u8]) -> Result<${pascal}Record, ${pascal}Error> {
        let text = std::str::from_utf8(frame).map_err(|_| ${pascal}Error::NotText)?;
        let text = text.trim();
        if text.is_empty() {
            return Err(${pascal}Error::Empty);
        }
        let fields: Vec<&str> = text.split(',').map(str::trim).collect();
        if fields.len() < 2 || fields.len() > 3 {
            return Err(${pascal}Error::Fields(fields.len()));
        }
        let number = |s: &str| -> Result<f64, ${pascal}Error> {
            let v: f64 = s.parse().map_err(|_| ${pascal}Error::Number(s.to_string()))?;
            if v.is_finite() {
                Ok(v)
            } else {
                Err(${pascal}Error::Number(s.to_string()))
            }
        };
        let lat = number(fields[0])?;
        let lon = number(fields[1])?;
        if !(-90.0..=90.0).contains(&lat) {
            return Err(${pascal}Error::Range(format!("latitude {lat}")));
        }
        if !(-180.0..=180.0).contains(&lon) {
            return Err(${pascal}Error::Range(format!("longitude {lon}")));
        }
        let alt_m = match fields.get(2) {
            Some(s) => Some(number(s)?),
            None => None,
        };
        Ok(${pascal}Record { lat, lon, alt_m })
    }

    /// Map a decoded record onto a canonical event. The entity type and the
    /// attribute names are the ones your operator agreed with you.
    pub fn to_event(&self, record: &${pascal}Record, raw: &[u8]) -> Result<Event, ${pascal}Error> {
        let mut builder = EventBuilder::new(&self.source_id, "mim:object")
            .new_id()
            .now()
            .location(record.lat, record.lon, record.alt_m.unwrap_or(0.0))
            // The raw frame rides inside the signed event, verbatim.
            .payload(raw.to_vec())
            // The feed's own identifier keeps each platform its own track. This
            // format has none, so the connector's identity stands in; replace
            // it with the native id (tail number, track number, MMSI, ...).
            .metadata("source_uid", &self.source_id);
        // Hostility is asserted by the operator, never invented here.
        if let Some(h) = self.enrichment.hostility.as_deref() {
            builder = builder.attribute("hostility", h);
        }
        builder.build().map_err(|e| ${pascal}Error::Build(e.to_string()))
    }
}

/// The one piece of glue that plugs this format into the shared runtime.
impl FrameParser for ${pascal}Parser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let record = self.decode(frame).map_err(|e| Box::new(e) as ParseError)?;
        self.to_event(&record, frame)
            .map(|event| vec![event])
            .map_err(|e| Box::new(e) as ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> ${pascal}Parser {
        ${pascal}Parser::new("test-1", Enrichment::default())
    }

    fn attribute<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
        event
            .attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    fn metadata<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
        event
            .metadata
            .iter()
            .find(|m| m.key == key)
            .map(|m| m.value.as_str())
    }

    #[test]
    fn a_good_frame_becomes_one_event_at_its_position() {
        let events = parser().parse(b"51.5074,-0.1278,35").unwrap();
        assert_eq!(events.len(), 1);
        let location = events[0].location.as_ref().expect("located");
        assert!((location.latitude - 51.5074).abs() < 1e-9);
        assert!((location.longitude + 0.1278).abs() < 1e-9);
        assert!((location.altitude_m - 35.0).abs() < 1e-9);
        assert_eq!(events[0].entity_type, "mim:object");
    }

    #[test]
    fn the_raw_frame_is_sealed_verbatim_in_the_payload() {
        let raw = b"51.5074,-0.1278";
        let events = parser().parse(raw).unwrap();
        assert_eq!(events[0].payload, raw.to_vec());
    }

    #[test]
    fn the_feed_identity_is_the_source_uid() {
        let events = parser().parse(b"1,2").unwrap();
        assert_eq!(metadata(&events[0], "source_uid"), Some("test-1"));
    }

    #[test]
    fn hostility_is_only_stamped_when_the_operator_set_it() {
        let plain = parser().parse(b"1,2").unwrap();
        assert_eq!(attribute(&plain[0], "hostility"), None);
        let enriched = ${pascal}Parser::new("test-1", Enrichment::default().with_hostility("Unknown"));
        let events = enriched.parse(b"1,2").unwrap();
        assert_eq!(attribute(&events[0], "hostility"), Some("Unknown"));
    }

    #[test]
    fn malformed_frames_are_refused_with_a_reason() {
        let p = parser();
        assert_eq!(p.decode(b""), Err(${pascal}Error::Empty));
        assert_eq!(p.decode(b"51.5"), Err(${pascal}Error::Fields(1)));
        assert_eq!(p.decode(b"north,west"), Err(${pascal}Error::Number("north".into())));
        assert_eq!(p.decode(b"91,0"), Err(${pascal}Error::Range("latitude 91".into())));
        assert_eq!(p.decode(b"\xff\xfe"), Err(${pascal}Error::NotText));
    }

    #[test]
    fn hostile_bytes_never_panic() {
        let p = parser();
        let mut seed: u32 = 0x9e37_79b9;
        for _ in 0..2_000 {
            let len = (seed % 64) as usize;
            let frame: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = p.parse(&frame);
        }
    }
}
EOF

cat > "$dir/src/main.rs" <<EOF
// SPDX-License-Identifier: Apache-2.0
//! <Your format> ingress connector.
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in \`ajar_connector_common\`.
//! This binary is only the wiring: read config, build the parser, open the
//! transport, run.

use ajar_connector_common::{open_source, run, Config};
use ajar_${snake}::${pascal}Parser;
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,async_nats=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    // The first non-flag argument is the config path, so \`--profile\` may sit on
    // either side of it.
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "$name.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // \`--profile\` prints the document the operator registers and exits,
    // before any transport is opened.
    if ajar_connector_common::profile::requested(&args) {
        println!("{}", ajar_connector_common::profile::emit(&cfg, &["mim:"])?);
        return Ok(());
    }

    let parser = ${pascal}Parser::new(cfg.source_id.clone(), cfg.enrichment());
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
EOF

cat > "$dir/$name.example.toml" <<EOF
# SPDX-License-Identifier: Apache-2.0
#
# Example config for $crate. Copy, adjust, and run:
#   $crate ./$name.toml
#
# A second feed is a second copy of this file with a different source_id, key
# and transport, no rebuild.

# This connector's Ajar identity. Its signing key (below) must be registered in
# Core against this same id.
source_id = "$name-1"

# Where Core listens. Production is tls://<host>:443 with the AJAR_TLS_* env set
# (see the repository README); nats://… is for local development only.
nats_url = "nats://127.0.0.1:4222"

# Publishes to <subject_prefix>.<source_id>. Leave as-is unless Core says otherwise.
subject_prefix = "ajar.ingest"

# The connector's own Ed25519 signing seed: 32 raw bytes, or a 64-char hex file.
# Secret — never commit it, never share it.
signing_key_path = "./$name-1.seed"

# Hostility to stamp on a feed that carries none. Leave unset to assert nothing.
# default_hostility = "Unknown"

# The security marking every event carries, stamped inside its signature.
# Every field is optional; see the repository README, section 7f.
# [marking]
# classification = "restricted"
# releasable_to = ["GBR", "ITA"]
# caveats = ["EXERCISE"]

# How bytes reach the connector. Any transport in the repository README's
# transport table works here; this one reads newline-delimited frames pushed
# over TCP. Others: udp, udp-multicast, tcp-client, http-server, file, dir,
# exec, stdin, pcap-replay, serial, mqtt, rest-poll, ws-client, dds.
[transport]
kind = "tcp-server"
bind = "0.0.0.0:9300"
framing = "line"
EOF

cat > "$dir/README.md" <<EOF
<!-- SPDX-License-Identifier: Apache-2.0 -->
# $crate

Ingress connector for **<your format>**. It decodes each native frame into a
canonical Ajar event, seals it with the connector's Ed25519 key, and publishes
it to Core.

## Model

\`\`\`
<your feed> ──▶ $crate ──▶ canonical Event ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
 untrusted edge     decode       (SDK)          (Ed25519)         (mTLS to Core)
\`\`\`

The connector holds no Core secrets, only its own signing key. Core trusts the
signature, not the pipe.

## What it decodes

| Native field | Canonical mapping | Unit |
|---|---|---|
| latitude, longitude, altitude | event location | degrees, metres |

Everything else in the frame is preserved verbatim in \`Event.payload\`.

## Configure and run

\`\`\`sh
cp $name.example.toml $name.toml   # edit source_id, key path, and [transport]
$crate ./$name.toml
$crate --profile ./$name.toml      # the document your operator registers
\`\`\`

## Conformance

\`cargo test -p $crate\` proves a frame decodes to one located event, that the
raw frame is sealed in the payload, that malformed input is refused with a
reason, and that hostile bytes never panic.
EOF

# Register the crate in the workspace: insert before the closing bracket of
# `members`. Portable across BSD and GNU tooling.
awk -v member="    \"$name\"," '
  /^members = \[/ { inmembers = 1 }
  inmembers && /^\]/ { print member; inmembers = 0 }
  { print }
' "$ws/Cargo.toml" > "$ws/Cargo.toml.tmp" && mv "$ws/Cargo.toml.tmp" "$ws/Cargo.toml"

# Line widths depend on the name, so format the generated sources the way the
# repository's gate expects them.
if command -v cargo >/dev/null 2>&1; then
  (cd "$ws" && cargo fmt -p "$crate" 2>/dev/null) || true
fi

cat <<EOF
created rust/connectors/$name  (crate $crate)

  src/$snake.rs
      the parser: edit decode() and to_event(), keep the tests honest
  src/main.rs
      the wiring; no changes needed
  $name.example.toml
      config: identity, key, transport
  README.md
      say what you decode and in which units

next:
  cd rust/connectors
  cargo test -p $crate                            # passes as generated
  cargo build --release -p $crate
  ./target/release/$crate --profile ./$name/$name.example.toml
EOF
