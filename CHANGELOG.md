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
- `ajar-klv` connector for STANAG 4609 / MISB ST 0601 (KLV) UAS motion-imagery
  metadata: decodes the platform tags (time, tail number, heading/pitch/roll,
  sensor position), validates the ST 0601 checksum fail-closed, and seals the
  entire raw KLV set into the signed `Event.payload` so unmapped tags are never
  lost. It also serves as the reference binary-format connector.
- `AGENTS.md`: a connector-authoring spec (the `FrameParser` contract, the
  losslessness / canonical-units / `source_uid` rules, which connector to copy,
  and the verify steps) so a connector for a new format can be added — by a person
  or a coding agent — by following one document.

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
