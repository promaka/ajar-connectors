# Vendored contract — provenance

These files are copied verbatim from the Ajar core repo (private). Do not edit
them here; re-vendor from core when the contract version changes.

- Source repo:   github.com/promaka/ajar (private)
- Source commit: 9560f8f
- Vendored on:   2026-06-12
- Files:
  - event.proto       <- core/event-schema/proto/event.proto
  - vectors.json      <- core/event-schema/tests/conformance/vectors.json
  - corpus/*.json     <- core/event-schema/tests/conformance/corpus/

The SDK MUST reproduce every `canonicalSha256` and `sealedSha256` in
vectors.json (signing seed is the published TEST seed — never production).
