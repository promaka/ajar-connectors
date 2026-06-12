# Vendored contract — provenance

These files are copied verbatim from the Ajar core repo (private). Do not edit
them here; re-vendor from core when the contract version changes.

- Source repo:   github.com/promaka/ajar (private)
- Source commit: da5094b   (golden vectors hardened: edge cases + namespaced fixtures)
- Vendored on:   2026-06-12
- Files:
  - event.proto       <- core/event-schema/proto/event.proto   (unchanged since 9560f8f)
  - vectors.json      <- core/event-schema/tests/conformance/vectors.json   (re-blessed, 6 fixtures)
  - corpus/*.json     <- core/event-schema/tests/conformance/corpus/   (3 namespaced + 3 edge cases)

The SDK MUST reproduce every `canonicalSha256` and `sealedSha256` in vectors.json
(signing seed is the published TEST seed — never production).
