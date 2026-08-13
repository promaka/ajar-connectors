<!-- SPDX-License-Identifier: Apache-2.0 -->
# AGENTS.md — authoring an Ajar connector

This file is the spec for adding a **new ingress connector** to this repo, written
so a coding agent (or a person) can follow it end to end. A connector turns one
native feed (a wire protocol, a legacy appliance's output, a STANAG set) into
**signed canonical Ajar events**. You write one thing: a parser. The runtime does
transport, key loading, mTLS NATS, sealing, health, and shutdown.

## The one interface you implement

```rust
pub trait FrameParser: Send + Sync + 'static {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError>;
}
```

`frame` is one unit as delivered by the configured transport. Return zero or more
canonical `Event`s. That is the whole contract.

## Non-negotiable rules

1. **Losslessness — seal the raw frame.** Put the exact bytes that produced the
   event into `Event.payload` (`.payload(raw)`), verbatim. Never decide a field is
   worthless by dropping it: anything you don't decode today must survive in the
   payload for a later ontology to extract. *A connector must not decide what is
   valuable.*
2. **Emit every decoded field as an attribute.** Use `.attribute(key, value)`.
   Core's ingest demotes undeclared keys to quarantine metadata — you do **not**
   gate on any ontology. Absent stays absent: never invent a default (including
   hostility — emit it only if the operator configured one).
3. **Canonical names + units.** Governed attributes have declared units. Normalise
   to them (speed → m/s, vertical_rate → m/s, altitude → metres, angles → degrees)
   and keep the native value in metadata (`speed_kn`, `altitude_ft`, …). A value in
   the wrong unit passes validation and is silently wrong. `heading` (where the
   platform points) ≠ `course` (track over ground).
4. **Native identity → `source_uid`.** Emit the feed's own id (ICAO, MMSI, sysid,
   tail number, track number) as the `source_uid` **metadata** key, so Core keeps
   each platform its own track. The event `id` is always a fresh UUID (`.new_id()`).
5. **Untrusted edge — never panic, never fabricate.** Bounds-check every read.
   Every failure is a typed error variant, not a panic or an unwrap on input. Reject
   malformed/oversized frames fail-closed.
6. **Any per-entity buffer must be bounded** (drop-oldest over a cap) and, if it
   drops, mark the event `payload_truncated=true` and count it. Only needed for
   connectors that correlate across frames — see `adsb`/`ais-nmea`.

## Which worked example to copy

- **Binary / bit-packed** (STANAG, TLV, framed records): copy **`klv`** (MISB ST
  0601, tag-length-value) for a tag-based format, **`gmti`** (STANAG 4607) for an
  existence-mask / segmented-packet format, **`asterix`** (EUROCONTROL CAT021/048/062 — FSPEC + compound items), or **`stanag4586`** (NATO UAS Control DLI — fixed-field big-endian wrapper + checksum, multi-message datagram).
- **XML** (situational-awareness / track feeds): copy **`tak-cot`** (Cursor-on-Target)
  for a flat attribute form, or **`stanag4676`** (NATO ISR Tracking — nested
  nitsRoot/track/segment/tp, namespace-prefix-agnostic, one event per track point).
- **Line/text records** (JSON, CSV, NMEA-like): copy **`ais-nmea`**, or use the
  config-driven **`generic`** connector with no new code at all if the feed is
  newline JSON/CSV.
- **Correlated multi-frame** (identity in one frame, position in another): copy
  **`adsb`** or **`mavlink`** for the carry-forward pattern.

## Files to produce (mirror an existing connector exactly)

```
rust/connectors/<name>/
  Cargo.toml            # copy asterix/Cargo.toml; rename to ajar-<name>
  src/lib.rs            # pub mod <name>; re-export the Parser + Error + record types
  src/<name>.rs         # the parser: struct, error enum, FrameParser impl, tests
  src/main.rs           # ~20 lines of wiring; copy asterix/src/main.rs verbatim,
                        #   swap in your Parser type
  <name>.example.toml   # copy an existing one; set source_id, key path, transport
  README.md             # what it decodes, what rides in payload, units
```

Then add `"<name>"` to `members` in `rust/connectors/Cargo.toml`. Transports are
config, not code — never write socket/file I/O; pick a `[transport]` kind in the
TOML (`udp`, `tcp-server`, `tcp-client`, `serial`, `file`, `dir`, `exec`, `stdin`,
`mqtt`, `rest-poll`).

## EventBuilder cheat-sheet

```rust
EventBuilder::new(source_id, "mim:aircraft")   // namespaced entity type
    .new_id()                                   // fresh UUIDv7 event id
    .location(lat, lon, alt_m)                  // WGS-84 degrees, metres
    .timestamp(rfc3339) / .now()                // observation time
    .payload(raw_bytes)                         // RULE 1: the raw frame, verbatim
    .attribute(key, value)                      // RULE 2: every decoded field
    .metadata("source_uid", native_id)          // RULE 4: native identity + non-tactical ids
    .confidence(0.0..=1.0)                       // optional
    .build()?                                    // validates; propagate the error
```

## How to verify (must all pass before opening a PR)

```sh
cd rust/connectors
cargo test  -p ajar-<name>                       # unit tests you wrote
cargo clippy -p ajar-<name> --all-targets -- -D warnings
cargo fmt   -p ajar-<name> --check
cargo build --workspace                          # nothing else broke
```

Write tests from **real captured frames** where possible. For a format that a
legacy appliance *claims* to speak but mangles, capture what it actually emits
first (deploy a connector that seals raw and inspect `Event.payload`), then write
the parser against those real bytes and iterate until the tests pass. Include at
minimum: a happy-path decode, a checksum/validation-reject, a truncated-input
reject (proves no panic), and a raw-preserved-in-payload assertion.

## Definition of done

All four commands above pass; the connector seals raw into payload, emits decoded
fields as attributes with canonical units, sets `source_uid`, and never panics on
malformed input. That's a mergeable connector.
