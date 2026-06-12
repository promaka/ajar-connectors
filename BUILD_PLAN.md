<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connectors — SDK Build Brief

## 0. What this repo is
The Apache-2.0, vendor-facing SDK for building connectors to Ajar — the sovereign
defence integration/governance plane. A connector turns a vendor/legacy system's
native data into Ajar's canonical, signed event (inbound), and/or translates
governed events into a target system's format (outbound). This repo is
standalone: it must never depend on the private Ajar core. It earns trust by
reproducing the golden vectors — proving byte-for-byte compatibility with what
Ajar accepts.

## 1. Hard constraints (do not violate)
- **License:** Apache-2.0. Add LICENSE + SPDX headers. DCO sign-off (`git commit -s`).
- **No dependency on Ajar core.** Generate types from the vendored `event.proto`;
  reimplement the (tiny) seal spec from §5. Importing a private `ajar-*` crate is forbidden.
- **Byte-compatibility is the acceptance test.** The SDK must reproduce every hash
  in the vendored `vectors.json` (§6). If it doesn't, it's wrong.
- **Language order:** Rust first (mirrors core, validates the harness in-language),
  then Go, then Python — same vendored contract, same vectors.
- **No secrets.** The golden signing seed is TEST-ONLY; never use it for production signing.

## 2. What to vendor from core
Copy two files from the core repo into `vendor/contract/`:
- `core/event-schema/proto/event.proto` → `vendor/contract/event.proto`
- `core/event-schema/tests/conformance/vectors.json` → `vendor/contract/vectors.json`
- (and the `corpus/*.json` fixtures referenced by the vectors)

Add a `CONTRACT_VERSION` note and a CI check that flags if the vendored copy
diverges from a known hash (manual bump for now, since core is private).

## 3. The Event contract (what a connector produces)
Fields (from `event.proto`, all lower-camel in JSON, snake in Rust):
- `schema_version` = "v1"
- `id` — UUIDv7 string
- `source_id` — the connector's stable source identity
- `entity_type` — namespaced controlled vocab: `mim:<type>` (standards base) or
  `x:<vendor>:<type>` (extensions)
- `timestamp` — RFC 3339 (source observation time)
- `received_at` — leave empty; Ajar stamps its own clock
- `location` — optional GeoPoint { latitude, longitude, altitude_m }
- `payload` — opaque bytes, kept small (a reference/metadata, never bulk media)
- `policy_tags` — ≤ 64; carries markings like `class:secret`, `rel:DEU`
- `confidence` — 0.0..=1.0
- `attributes` — ≤ 128 { key, value }, MUST be sorted by key, unique (canonical rule)

## 4. Canonical bytes (what gets hashed & signed)
`canonical_bytes` = deterministic protobuf encoding (`prost` `encode_to_vec`; no
map fields). The attributes rule is load-bearing: unsorted or duplicate keys
produce non-canonical bytes that Ajar rejects. → Build an `EventBuilder` that
auto-sorts attributes and rejects duplicate keys, so a connector author cannot
emit non-canonical events.

## 5. The seal envelope (authentication)
```
sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
         └────────── 64-byte detached signature ──────┘
```
Detached Ed25519, signature prefixed. Provide `seal(canonical, signing_key) -> Vec<u8>`.
Each production connector holds its own key; Ajar registers the matching public
key in the connector's profile.

## 6. The conformance test (THE deliverable)
Load `vendor/contract/vectors.json`. It contains a TEST `signingSeedHex` (32×0x47),
the derived `verifyingKeyHex`, and per-fixture `canonicalSha256` + `sealedSha256`.
For each corpus fixture, the SDK must:
1. build the Event, compute `canonical_bytes`, assert SHA-256 == `canonicalSha256`;
2. seal it with the TEST seed, assert SHA-256 == `sealedSha256`.

This passing == the SDK is byte-compatible with Ajar. It is the gate.

## 7. Public API to build (Rust crate `ajar-connector`)
- generated Event/GeoPoint/Attribute types (from vendored proto)
- `EventBuilder` — ergonomic, auto-sorts/validates attributes, enforces required
  fields, UUIDv7 + RFC3339 helpers
- `canonical_bytes(&Event) -> Vec<u8>`
- `seal(&[u8], &SigningKey) -> Vec<u8>`
- `ConnectorProfile { source_id, allowed_entity_types, max_payload_bytes,
  rate_capacity, rate_refill_per_sec, verifying_key }` — declaration helper + serializer
- a `Connector` trait: `fn normalize(&self, native: &[u8]) -> Result<Event, _>`
- outbound mirror: an `OutboundProfile` trait — `target()`, `slug()`, `version()`,
  `modeled_fields()`, `lossy_fields()`, `render(&Event) -> Vec<u8>`, with round-trip
  conformance tests (canonical → target → canonical)
- (later) actuation connector trait: addressed, acknowledged, fail-safe cue
  delivery — gated behind a clear "safety-critical" doc; the human-approval/
  authorization lives in Ajar core, not the SDK

## 8. Repo structure
```
ajar-connectors/
  LICENSE  README.md  BUILD_PLAN.md (this)
  vendor/contract/        event.proto, vectors.json, corpus/
  rust/
    ajar-connector/       src/ (the SDK crate)
    examples/             a reference connector (e.g. CoT/radar → canonical)
    conformance/          the golden-vector test (§6)
  .github/workflows/      ci: fmt, clippy -D warnings, test, conformance, license-header
```

## 9. First milestone (Rust)
1. Generate types from vendored proto; `canonical_bytes` reproduces `canonicalSha256`
   for all fixtures.
2. `seal` reproduces `sealedSha256`. Conformance green = milestone done.
3. `EventBuilder` with attribute auto-sort + validation.
4. One reference inbound connector example (e.g. CoT XML or a CSV radar feed →
   canonical event), end-to-end with a generated signing key.
5. README: "write your first connector in 20 lines."

## 10. Explicitly NOT in scope
The SDK does not implement policy, audit, ontology enforcement, correlation, or
the pipeline — that's core's job. The SDK only produces valid signed events,
declares profiles, and translates in/out. It never sees secrets beyond a
connector's own signing key.

---

## Implementation notes (as built)
- Types are generated from `vendor/contract/event.proto` with `prost-build`,
  using `protoc-bin-vendored` so `cargo build` needs no system `protoc`.
- `received_at` is **not** exposed on `EventBuilder` (Ajar stamps it), but the
  conformance loader sets it from each fixture so canonical bytes match the
  blessed vectors byte-for-byte.
- `EventBuilder` enforces `mim:`/`x:` entity-type namespacing by default, with an
  `allow_unnamespaced_entity_type()` opt-out for migration.
- Contract divergence + license headers are guarded by `scripts/*.sh`, wired into CI.
