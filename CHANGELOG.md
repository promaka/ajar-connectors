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

### Added

- Generic egress can label every delivered object with a STANAG 4774-shaped
  confidentiality label, projected from the event's policy tags: `class:*`
  becomes the classification, `rel:*`/`releasable:*` become a Releasability
  category, under a deployment-configured policy identifier. A projection by
  design: enforcement is unchanged everywhere, classification vocabulary
  passes through rather than being reinterpreted, `policy_tags` remain in
  every delivered object as the source of truth, and the block is opt-in so
  no existing consumer's format changes. The binding of label to data is the
  sealed envelope the tags already live in, signed at origin and re-signed
  by the egress authority.

### Fixed

- A comma-separated `nats_url` now actually fails over. The list form was
  accepted but reached the client as one unparseable address, so a two-box
  config never connected. The connection layer splits the list, any `tls://`
  entry demands TLS for the whole connection, and a gate pins the behavior
  against two real brokers: kill the connected box and the survivor carries
  the traffic.

### Changed

- The shipped `ajar-ais-nmea` binary reads serial out of the box: real
  bridges deliver NMEA over RS-422/RS-232, so the `serial` transport is now a
  default feature of that connector instead of a source-only build option.
  `--no-default-features` restores the lean build. The example config shows
  the serial block and the usual permission fix.

## [0.5.8] - 2026-09-01

### Added

- `ajar_connector.producer` (Python, `pip install "ajar-connector[producer]"`):
  a drop-in module for platforms that consume governed events and publish
  derived assessments back. `connect()` returns a handle (mTLS, fail-closed on
  partial TLS config); `publish_assessment()` builds, seals and publishes one
  event, with `model` and `derived_from` as required arguments because the
  boundary refuses derived events without lineage. The envelope is the SDK's
  `seal()`, byte-identical to any connector's, and every publish carries
  `Nats-Msg-Id`. The wire gate runs against a real nats-server in CI, and
  `examples/derived_producer.py` shows the consume-derive-publish loop end to
  end; the one call a platform adds is marked in the example.

### Added

- Store-and-forward disk spool (#76), for forward-deployed connectors on
  intermittent links. With `[spool]` configured, a connector that cannot reach
  NATS queues sealed events in a bounded on-disk segment log instead of
  shedding them, and replays them in order when the link returns: minutes of
  outage become replication lag, not loss. The spooled bytes are the sealed
  envelope exactly as the bus would have carried it, signed before publish, so
  replayed events verify under the connector's registered key with no
  re-signing and the observed_at/received_at delta is the replay evidence.
  The drain is paced (`drain_rate`, set from the operator's registered rate)
  because over-rate events are shed by the ingest limiter, and the replay
  cursor advances only on a JetStream publish acknowledgement (falling back
  to publish+flush against a plain-NATS sink). Bounding is drop-oldest, with
  drops counted; records that fail signature verification on drain (disk
  corruption) are counted and skipped, never published. Spool depth and drain
  progress are exposed on `/metrics`. One line enables it
  (`spool = "/var/lib/ajar/spool"`); the `[spool]` table tunes the bound and
  pace. `ajar-doctor` gains a spool step: it proves the directory is writable,
  reports any backlog waiting to drain, and teaches the one-liner when no
  spool is configured. The acceptance gate runs a real nats-server in CI:
  killed mid-stream, restarted, every outage event delivered byte-identical
  exactly once at the paced rate.

### Added

- `ajar-doctor`: one command to run when a connector publishes nothing. It
  walks the onboarding steps in order against the connector's own config and
  environment: config parse, signing key format and permissions, registration
  (against a local sink's `sources_dir`, or printing the exact public key the
  operator must hold), DNS and TCP reach, the fail-closed TLS policy table,
  certificate files (pair match, CN = `source_id`, validity), a live TLS
  handshake with named causes (wrong CA, missing or mismatched SAN, expired or
  postdated certificates, a server refusing the client certificate, an
  authorization refusal after a good handshake), and clock skew against the
  server certificate's validity window. Every failure prints what to do, not
  just what went wrong. Read-only on the wire: it never publishes an event.
  With a config file it reads exactly what the connector reads; with none it
  reads `NATS_URL`, `AJAR_SOURCE_ID` and `AJAR_SIGNING_SEED`, so a connector
  embedded in your own process is diagnosed with zero files.
  Each diagnosis is pinned by an integration suite that fabricates its failure
  mode against real listeners on loopback.

### Fixed

- Every connector publish now sets the `Nats-Msg-Id` header to the event id.
  Core's ingest stream has always kept a 120-second duplicate window keyed on
  that header; no publisher sent it, so retransmissions and reconnect races
  could be stored twice. The shared runtime and the Rust, Go and Python
  examples set it on every publish, and each SDK now carries the contract as
  code for embedders publishing with their own NATS client:
  `ingest_headers(event)` (`IngestHeaders` in Go) returns the headers an
  ingest publish must carry, alongside the `NATS_MSG_ID_HEADER` constant.

## [0.5.7] - 2026-08-29

### Added

- Line coverage is measured in CI on every pull request and shipped library
  and connector code holds an 85% floor: a change that lowers coverage fails
  the build. Binary entrypoints are scoped out of the measurement, being
  proven by the CI gates that run the real binaries. At introduction the SDK
  measures 92% and the connectors workspace 86%.
- The transport layer gains an integration suite against real sockets, files,
  directories and child processes: appends and rotation for the file tail,
  settled drops for the directory watch, respawn-on-exit for exec, reconnect
  for the TCP client, pushers for the TCP server, datagram framing for UDP,
  the health endpoint's counters, and the fail-closed TLS policy including
  every partial-configuration state.
- The Rust SDK is published to crates.io as `ajar-connector` on release, gated
  on the golden vectors, with crates.io Trusted Publishing so no long-lived
  credential exists in the repository. The crate carries its own copy of the
  vendored `event.proto`, held byte-identical to `vendor/contract` by the
  contract guard, so a published package builds standalone with no system
  protoc.

### Added
- `cargo-deny` runs on every pull request across all three workspaces:
  RUSTSEC advisories, a licence allow-list, duplicate-version warnings, and
  crates.io as the only permitted dependency source. Exceptions are recorded
  with their reasons in `deny.toml`.
- The Linux release tarballs include the demo publisher alongside the
  connectors and the sink, so the publish, verify, chain and audit loop runs
  from the artefacts alone on an air-gapped host.

### Fixed
- Releases now create a `go/vX.Y.Z` tag alongside the release tag. Go resolves
  a module in a subdirectory through a tag carrying the directory prefix, so
  this is what makes `go get .../go/ajarconnector@vX.Y.Z` resolve; `go/v0.5.6`
  is published for the current release.
- TLS certificate and key parsing moves from the unmaintained `rustls-pemfile`
  (RUSTSEC-2025-0134) onto `rustls-pki-types`. Yanked `chacha20` and `spin`
  versions are updated out of the lockfiles.

## [0.5.6] - 2026-08-22

### Added
- The AIS/NMEA connector decodes ARPA radar tracked targets (`$--TTM`) from the
  same feed: the radar picture beside the transponder picture, one connector,
  one config. Targets are geolocated from own-ship GGA/RMC fixes on the bus, or
  from a fixed `[sensor]` site for a shore-mounted radar; without an observer,
  or with a relative bearing, the measurement rides as metadata and no position
  is guessed. Targets are `mim:object` on the surface — a radar return is a
  detection, not a classification — with the radar's target number as the
  stable native identity.

### Added
- `ajar-generic-egress`: governed events out of Ajar, delivered to a consumer
  endpoint as JSON in the consumer's field names. Every payload is verified
  under Core's egress signature before it is mapped or delivered, with no off
  switch. The event id, the policy markings and the governance block are present
  in every delivered object regardless of mapping; unmapped governed content is
  delivered or refused, never silently dropped. Subscriptions are confined to
  `ajar.egress.` so the effector cue channel is structurally out of reach.
  Delivery is at-most-once on the live leg, bounded, with every loss counted.

## [0.5.5] - 2026-08-21

### Added
- `ajar-sink`, a development and evaluation sink: verifies each sealed event
  against its publisher's registered key, persists it, links every record into a
  hash chain, and proves the record afterwards with `audit`. Ships in the Linux
  release tarballs. A compose stack under `deploy/dev` runs the whole loop on
  one machine.
- The development sink can render each verified event as Cursor-on-Target onto
  ATAK's mesh SA multicast group, so a TAK client on the same network shows the
  live picture with no server and no setup. Off unless configured; events
  without a location are skipped rather than mapped at (0,0); the outgoing
  interface is pinnable because multicast on a multi-homed host otherwise leaves
  on the default route and fails silently. The README gains a five-minute
  demo section around it.
- C++ mapping validation against the vendored ontology: `ajar::validate()` over
  a declared mapping or a built event, and a `--check` flag on the connector
  template for CI. The same checks the Rust runtime applies at startup — unknown
  entity type, ungoverned attribute, value outside a controlled vocabulary, case
  slips answered with the correction — now reach embedders linking the SDK, from
  the release tarball, offline. Validation is advisory at the API level; refusing
  to start on faults is the embedder's decision.

### Changed
- The only key value in the repository is now the conformance seed the golden
  vectors publish. The demo stack mints a fresh keypair at startup and registers
  it through the sink's new `sources_dir`; dry-run modes across all four
  language examples mint an ephemeral throwaway key per run. CI scans the full
  git history with gitleaks on every pull request.

## [0.5.4] - 2026-08-20

### Fixed
- Connectors install a rustls crypto provider explicitly. rustls 0.23 selects one
  from crate features only while exactly one is compiled in, so a dependency
  pulling a second turned that into a failure before the first byte reached the
  network. The dependency graph is also reduced to one rustls and one provider
  with every feature enabled.

### Added
- A CI gate builds a connector image from the checkout, starts NATS with
  `verify_and_map` and a P-256 client certificate, and asserts the connector
  completed mTLS and published. The unit tests exercise the TLS policy without
  opening a socket, so they stayed green whether or not a shipped binary could
  complete a handshake.
- `vendor/contract/ontology.json`, hash-pinned beside `event.proto`. Connectors
  validate their declared mapping against it at startup: an unknown entity type,
  an attribute no ancestor of that type governs, or a value outside a controlled
  vocabulary stops the connector with a message naming the offender, rather than
  being discarded downstream without an error.
- `docs/mapping-to-mim.md`, which states what to map a feed to: the entity types,
  the governed attribute names and their units, the controlled vocabularies, and
  a worked example in C++ and Python.

### Changed
- The README leads with a contents table and four numbered setup paths, and the
  C++ guide with the four steps a partner takes in order.

### Added
- The Python SDK is published to PyPI as `ajar-connector` on release, gated on it
  reproducing the golden vectors first. Authentication is PyPI Trusted Publishing,
  so no API token exists in this repository to be stolen; artefacts carry signed
  SLSA provenance and PEP 740 attestations, matching the container images.
- `docs/embedding-python.md`, for partners linking the SDK into their own service
  rather than running one of our connectors.
- `scripts/check-versions.sh` holds every language manifest to the release
  version, run on each pull request and again before a tag can publish anything.

### Fixed
- The Python package version was `0.1.0`, five releases behind everything else,
  so publishing it would have shipped a version number that meant nothing. The
  C++ project declared no version at all; it now declares one.

### Added
- `--profile` on every connector prints the profile document the operator
  registers, derived from the config the connector already parses and the key it
  already holds, and exits before opening a transport. Onboarding previously
  asked a vendor to hand-write that document, or to write Rust to produce it.
  `allowed_entity_types` are prefixes, which is what lets an open-ended connector
  declare itself: `tak-cot` emits `["mim:", "x:cot:"]`, covering the unbounded
  `x:cot:<type>` fallback no enumeration could cover. Rate limits are omitted:
  they are the operator's policy, not the connector's to assert.

## [0.5.3] - 2026-08-19

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
- Install instructions across README, ONBOARDING, COMPATIBILITY and
  CONNECTOR_BRIEF pinned `v0.1.0`, five releases behind. They now pin the current
  release, and a guard fails the build when any documented pin drifts.

### Added
- The Helm chart is packaged and published to `oci://ghcr.io/promaka/charts` on
  release, versioned with the suite it deploys.
- `connector.name` resolves the image to the published connector of that name, so
  deploying a shipped connector no longer means knowing the registry path.
  `image.repository` still takes precedence for a connector you built yourself.
- Release binaries for `x86_64` and `aarch64` Linux, attached to the release with
  SHA-256 sums, for evaluators and air-gapped sites that cannot pull images.

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
