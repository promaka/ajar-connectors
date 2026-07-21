# Vendored contract — provenance

These files are copied verbatim from the Ajar core repo (private). Do not edit
them here; re-vendor from core when the contract version changes.

- Source repo:   github.com/promaka/ajar (private)
- Source commit: da5094b   (golden vectors hardened: edge cases + namespaced fixtures)
- Vendored on:   2026-06-12
- Files:
  - event.proto       <- core/event-schema/proto/event.proto   (metadata = 12 synced 2026-07, ADR-0030; additive, stays contract-v1)
  - vectors.json      <- core/event-schema/tests/conformance/vectors.json   (6 fixtures core-blessed; see note below)
  - corpus/*.json     <- core/event-schema/tests/conformance/corpus/   (3 namespaced + 4 edge cases)

Note on `edge_metadata_passthrough`: this fixture and its hashes were generated
SDK-side with the Rust reference implementation (proven byte-identical to core
on the six core-blessed vectors and a live core loopback) to cover the
`metadata = 12` field across all SDKs. Core should re-bless it at the next
vector regeneration (`AJAR_BLESS_VECTORS=1`) to make it core-authoritative.

The SDK MUST reproduce every `canonicalSha256` and `sealedSha256` in vectors.json
(signing seed is the published TEST seed — never production).
