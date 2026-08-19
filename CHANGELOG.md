<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project are recorded here. The format is based on
Keep a Changelog (https://keepachangelog.com).

Two version lines are tracked independently (see COMPATIBILITY.md):

- **SDK** — semantic versions (`v0.x` for now). The source API may change between
  minor versions before `1.0`; none of those changes alter the wire bytes.
- **Wire contract** — `contract-v1`, frozen and additive-only. A connector built
  against `v0.1.0` stays accepted without rebuilds.

## [Unreleased]

### Fixed
- `synthetic-radar` now reads its signing seed from `AJAR_SIGNING_SEED`, the
  variable every connector template, the keygen script and the Helm chart already
  use. It previously read `AJAR_SEED_FILE`, so a chart-deployed instance silently
  fell back to the published dev seed and signed events with a test key. Without
  a seed it now refuses to publish rather than signing; the dev seed remains
  reachable under `--dry-run`, where nothing leaves the process.
- The Helm chart now renders the connector's TOML into a ConfigMap and passes its
  path as the container's first argument. Connectors on the shared runtime read
  their identity, transport and key path from that file, so the chart previously
  produced a pod that could not start.

## [0.5.2] - 2026-08-18

### Added
- Published container images for the ASTERIX (`ajar-asterix`) and TAK/CoT
  (`ajar-tak-cot`) ingress connectors, built for `linux/amd64` and `linux/arm64`
  alongside the existing five.

## [0.5.1] - 2026-08-15

### Changed
- The GitHub release is now created by CI once every image it refers to has been
  pushed, rather than by hand beforehand. A failed image build leaves no release
  instead of a half-built one, and a tag with no matching `CHANGELOG.md` section
  fails rather than publishing empty notes.

## [0.5.0] - 2026-08-07

### Added
- **STANAG 4586** (NATO UAS Control) telemetry-ingest connector
  (`ajar-stanag4586`) — ingests the Data Link Interface (DLI) vehicle-state reports
  that `ajar-mavlink` complements for small/commercial UAS. (4586 spans UCS control
  Levels of Interoperability 1–5; this connector ingests telemetry, it does not
  command vehicles.) Parses the fixed-field big-endian message wrapper (validating
  each message's checksum fail-closed and bounds-checking a multi-message datagram),
  and decodes Message #101 Inertial States into a canonical track: WGS-84 position
  from the radian lat/lon, ground speed and course from the North/East/Down velocity
  vector, climb-positive vertical rate, and heading (from yaw) kept distinct from
  course. The vehicle id becomes `source_uid`; the raw message is sealed verbatim.
  The message model is implemented from the public NATO UNCLASSIFIED STANAG 4586
  Edition 2 field tables; an open reference implementation was consulted only to
  disambiguate the wrapper length — no code was copied (it is GPL-licensed) and its
  native-endian packing was not followed.

## [0.4.0] - 2026-08-06

### Added
- **STANAG 4676** (NATO ISR Tracking Standard, AEDP-12 Edition B) ingress
  connector (`ajar-stanag4676`) — the fused **track layer** above raw ISR
  detections, complementing `ajar-gmti`. Decodes `nitsRoot` track messages into one
  canonical event per track point: the Base64-encoded track UUID becomes
  `source_uid`; WGS-84 `<dynamics>` position yields the fix, with ground speed and
  course derived from the native degrees-per-second velocity vector; point time is
  reconstructed from `baseTime + relTime × relTimeIncrement`; segment status maps to
  new/update/coast/drop; STANAG 1241 identity drives affiliation (conservatively);
  and the STANAG 4774 confidentiality label rides as the event's policy tag. Matches
  on local element names so any namespace prefix decodes identically. The field
  model is cross-checked against the `bradh/jim` Edition-B reference implementation.

## [0.3.0] - 2026-08-06

### Added
- ASTERIX **CAT048** (monoradar target reports) and **CAT062** (SDPS system
  tracks), extending the ASTERIX connector from CAT021 alone to the full air
  picture: cooperative (CAT021), primary radar (CAT048), and the fused recognised
  track (CAT062). CAT048 reports are range/azimuth relative to the radar and are
  forward-geolocated against a configured `[sensor]` site; CAT062 carries WGS-84
  position and fused kinematics directly. Field layouts cross-checked against the
  python-asterix and Wireshark reference decoders.
- `[sensor]` config (`lat` / `lon` / `alt_m`) for connectors that report
  sensor-relative positions (used by ASTERIX CAT048 geolocation).

### Changed
- The ASTERIX decoder is now a category-generic FSPEC/UAP engine with a recursive
  length model for compound items (I048/130, I062/380, and friends), so adding a
  category is a UAP table plus a small decoder rather than new parsing logic.
  CAT021 behaviour is unchanged.


## [0.2.1] - 2026-08-05

### Fixed
- Align `ed25519-dalek` across the SDK and connector workspaces (both 3.x). A
  dependency bump had moved the SDK to 3.0 while the connectors stayed at 2.x, so a
  fresh-resolve build (the release image) pulled two incompatible majors and the
  `SigningKey` types no longer matched.

### Changed
- CI now builds, lints, and tests the `rust/connectors` workspace on every change
  (it previously built only the SDK and `examples` workspaces), so a connector
  break can no longer reach a release image undetected.
- Dependabot now tracks all three cargo workspaces (`rust`, `rust/connectors`,
  `rust/examples`) so dependency bumps stay aligned across them.


## [0.2.0] - 2026-08-05

### Added
- **Raw-payload losslessness.** Every inbound connector seals the raw wire frame(s)
  that produced an event verbatim into the signed `Event.payload`, so a field the
  parser does not yet map is never lost. Correlating connectors (`adsb`, `mavlink`,
  `ais-nmea`) carry non-emitting frames forward per entity into the next event they
  contribute to — bounded (drop-oldest over cap), with a `payload_truncated` marker
  and a `connector_dropped_carryforward_total` metric.
- `ajar-klv` connector — STANAG 4609 / MISB ST 0601 (KLV) UAS motion-imagery
  metadata. Decodes the platform tags, validates the ST 0601 checksum fail-closed,
  and seals the whole raw KLV set into the payload. The reference tag-length-value
  binary connector.
- `ajar-gmti` connector — STANAG 4607 (NATO GMTI) ground moving-target radar.
  Decodes the Dwell segment via its existence mask (sensor geometry, dwell area,
  per-target position and radial velocity), one event per detection, with the raw
  dwell segment sealed in the payload. `source_uid` is unique per detection (GMTI
  carries no persistent track id). The reference existence-mask / segmented-packet
  binary connector.
- `AGENTS.md` — a connector-authoring spec (the `FrameParser` contract, the
  losslessness / canonical-units / `source_uid` rules, which connector to copy, and
  the verify steps) so a connector for a new format can be added, by a person or a
  coding agent, by following one document.

### Changed
- **Canonical units (ADR-0019).** Speeds normalise to m/s, vertical rate to m/s,
  altitude to metres, with the native value kept in metadata (`speed_kn`,
  `vertical_rate_ftmin`, `altitude_ft`). Every decoded field is emitted as an
  attribute and Core's signed ontology governs which are kept, so the per-connector
  `governed_attributes` / Tactical mechanism is removed. `ATTRIBUTES.md` now points
  at Core's ontology manifest rather than restating it.
- Connector images cross-compile arm64 (`aarch64-unknown-linux-gnu`) on the native
  amd64 runner instead of emulating under QEMU, so arm64 (AWS Graviton, Raspberry
  Pi) builds at native speed.

### Fixed
- **AIS multi-fragment reassembly** is keyed on `(talker, channel, seq)`, not the
  sequential message id alone. An interleaved multipart message from another vessel
  can no longer splice its fragment into another vessel's reassembly — and, with the
  raw now sealed into a signed event, into its provenance record. Orphaned partials
  are discarded on a TTL sweep so a lost fragment cannot be completed later by an
  unrelated vessel.
- **MAVLink** logs each system id on first sight, and the example config documents
  the unique-`SYSID_THISMAV` requirement, so two vehicles that both kept the
  autopilot default (sysid 1) are visible to the operator rather than silently
  merged into one track.

## [0.1.0] - 2026-06-24

### Added
- Connector SDKs in Rust, Go, Python, and C++ that build, canonically encode
  (deterministic protobuf), and seal (Ed25519) events. All four are
  byte-compatible, proven by the shared golden vectors in
  `vendor/contract/vectors.json`.
- A minimal copy-me `connector-template` for each language: change two marked
  spots (the record shape and the mapping) and run.
- A per-language conformance gate proving byte-identity with `contract-v1`.
- mTLS to NATS in the templates via `AJAR_TLS_CA` / `AJAR_TLS_CERT` /
  `AJAR_TLS_KEY`, with a plaintext fallback for local development.
- Connector resilience: malformed records are logged and skipped, publish errors
  are non-fatal with automatic reconnect, and an optional `/healthz` + `/metrics`
  endpoint via `AJAR_HEALTH_ADDR`.
- A reference Dockerfile and Helm chart for deploying a connector, including
  liveness/readiness probes and a digest/pinned-tag requirement.
- Documentation: `ONBOARDING.md`, `HOW_IT_WORKS.md`, `COMPATIBILITY.md`,
  `CONNECTOR_BRIEF.md`, and `SECURITY.md`.

[Unreleased]: https://github.com/promaka/ajar-connectors/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/promaka/ajar-connectors/releases/tag/v0.1.0
