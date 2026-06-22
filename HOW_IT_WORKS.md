<!-- SPDX-License-Identifier: Apache-2.0 -->
# How Ajar connectors work — a detailed explanation

This document explains the *mechanics* of the connector system end to end: what
a connector is, what it produces, why the bytes are shaped the way they are, how
trust is established without a shared codebase, and how it all gets deployed.

If [ONBOARDING.md](ONBOARDING.md) is the "what do I type" guide, this is the
"what is actually happening and why" guide. Read it once and the rest of the repo
stops being mysterious.

---

## 1. The one-sentence model

> A connector turns your system's native data into a small, **canonically
> encoded**, **cryptographically signed** event, and publishes it onto a message
> bus. Ajar Core, somewhere else, pulls it off the bus, verifies the signature
> against a key you pre-registered, checks it against policy and an ontology, and
> stores it.

Everything below is an unpacking of that sentence.

The crucial design choice: **trust lives in the signature, not in the network
path.** The connector and Core never talk directly and never share code. They
agree on exactly two things: a **byte format** (the contract) and a **public
key** (your identity). That's the entire trust surface.

---

## 2. The four actors

```
  ┌──────────────┐     ┌───────────────────────┐    ┌──────────┐    ┌──────────────────────┐
  │ your system  │ ──▶ │ your connector        │ ──▶│  NATS    │──▶ │ Ajar Core            │
  │ (radar, AIS, │ raw │ (your code + this SDK)│    │ (broker) │    │ verify→policy→       │
  │  API, sensor)│     │ build→seal→publish    │    │          │    │ ontology→store       │
  └──────────────┘     └───────────────────────┘    └──────────┘    └──────────────────────┘
     you run it          you run it (the edge)        either side      operator runs it (C2/hub)
                         holds the PRIVATE key         runs it          holds your PUBLIC key
```

| Actor | Who runs it | What it holds | Its job |
|-------|-------------|---------------|---------|
| **Your system** | you (vendor) | your data | emits native records |
| **Your connector** | you (vendor), at the edge | the **private** signing key | map → sign → publish |
| **NATS** | whoever you agree on | nothing secret | a simple, fast message bus |
| **Ajar Core** | the operator (at C2/hub) | your **public** key | verify → govern → store |

The connector is the *only* piece you build. The SDK in this repo gives you the
hard parts (canonical encoding, signing); you write ~15 lines that map one of
your records into an event.

**Why NATS in the middle?** Because it decouples the two sides completely. The
connector opens an *outbound* connection to NATS and publishes; Core opens an
*outbound* connection to NATS and subscribes. Neither needs to know where the
other is, neither needs an inbound firewall hole, and events survive a lossy or
relayed link because authenticity rides in the signature, not the transport.

---

## 3. The data contract — the single source of truth

Everything hinges on one file: [vendor/contract/event.proto](vendor/contract/event.proto).
It is a Protocol Buffers (proto3) schema, package `ajar.event.v1`. Every SDK in
this repo (Rust, Go, Python, C++) generates its types **from this exact file**,
which is why they're byte-compatible.

### The `Event` message, field by field

| # | Field | Type | Meaning |
|---|-------|------|---------|
| 1 | `schema_version` | string | Always `"v1"`. The SDK sets it; you don't. |
| 2 | `id` | string | Globally unique event id. Use **UUIDv7** (time-ordered). |
| 3 | `source_id` | string | Your connector's stable identity, e.g. `acme-radar-1`. Ties to the key you registered. |
| 4 | `entity_type` | string | What this event *is*: `mim:aircraft`, `mim:vessel`, `x:acme:widget`… (see namespacing below). |
| 5 | `timestamp` | string | When **your source** observed it. RFC 3339 UTC. **Untrusted for ordering** — it's your clock. |
| 10 | `received_at` | string | When **Ajar** ingested it. Authoritative for ordering. **You leave this empty** — Core stamps it. |
| 6 | `location` | `GeoPoint` | Optional lat/lon/altitude. Structured so Core can index it in PostGIS. |
| 7 | `payload` | bytes | Opaque connector-specific blob. Keep it small (a reference, not bulk media). |
| 8 | `policy_tags` | repeated string | Access/routing markings, e.g. `class:secret`, `rel:DEU`. |
| 9 | `confidence` | double | Detection confidence in `[0.0, 1.0]`. |
| 11 | `attributes` | repeated `Attribute` | Type-specific key/value pairs (e.g. `heading=225`). **Must be sorted by key, unique.** |

`GeoPoint` is `{ latitude, longitude, altitude_m }` (doubles; altitude in metres
above the WGS84 ellipsoid). `Attribute` is `{ key, value }` — values are always
strings; the ontology on Core's side checks they satisfy the declared
datatype/unit/bounds.

### Two subtle but load-bearing rules

1. **`received_at` is Core's, not yours.** The schema has it (field 10) but the
   builder deliberately refuses to let you set it — it always writes empty
   ([builder.rs:180](rust/ajar-connector/src/builder.rs#L180)). Ordering and the
   audit chain follow Core's ingest clock plus a monotonic sequence, never the
   sender's `timestamp`. This is what makes a compromised or clock-skewed sensor
   unable to reorder history.

2. **`attributes` must be sorted by `key` with no duplicate keys.** This is the
   one canonical rule a connector author could violate by hand — and the SDK
   enforces it for you (see §5). Core *rejects* any event whose attributes are
   unsorted or duplicated, because that would make the bytes non-canonical.

### Entity-type namespacing

`entity_type` must be namespaced, in one of two forms
([builder.rs:192-203](rust/ajar-connector/src/builder.rs#L192)):

- `mim:<type>` — the standards base vocabulary (e.g. `mim:aircraft`). One colon,
  non-empty type.
- `x:<vendor>:<type>` — a vendor extension (e.g. `x:acme:widget`). Exactly two
  colons, both halves non-empty.

The builder enforces this by default and rejects a bare `drone` with
`UnnamespacedEntityType`. There's an escape hatch
(`allow_unnamespaced_entity_type()`) for migrating legacy feeds, but production
events should be namespaced so Core's ontology can resolve them.

---

## 4. What a connector actually does — the four steps

The whole connector is a loop of four steps. The SDK gives you 2–4; you write 1.

```
   your record  ──▶  build Event  ──▶  canonical bytes  ──▶  seal  ──▶  publish
   (step 1: YOU)     (EventBuilder)    (canonical_bytes)    (seal)    (NATS client)
```

Here is the core of it in Rust (the same shape exists in every language):

```rust
use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

// STEP 1 — NORMALIZE (the only Ajar-specific code you write):
let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
    .new_id()                       // UUIDv7
    .now()                          // RFC 3339 observation time
    .location(r.lat, r.lon, r.alt)  // your record's fields
    .confidence(r.quality)
    .build()?;                      // validates — can't emit a bad event

// STEP 2 — CANONICAL ENCODE:
let canonical = canonical_bytes(&event);

// STEP 3 — SEAL (sign):
let sealed = seal(&canonical, &signing_key);   // 64-byte sig ++ canonical

// STEP 4 — PUBLISH:
client.publish("ajar.ingest.acme-radar-1", sealed.into()).await?;
```

The subject is always `ajar.ingest.<source_id>`. Steps 2–4 are copy-paste from
the examples and never change. Step 1 is your integration.

### Building it — exactly what to change, where

The fastest path is to **copy a template and edit two spots.** Concretely, using
the Rust template ([rust/examples/connector-template/src/main.rs](rust/examples/connector-template/src/main.rs)):

**1. Copy the template** into your own project (or edit it in place to try it):

```bash
cp -r rust/examples/connector-template my-connector
```

**2. `EDIT 1` — describe one record from your feed.** Replace the `MyRecord`
struct's fields with whatever your feed actually produces. This is just a plain
data shape for *your* input:

```rust
// BEFORE (matches the demo JSON):
struct MyRecord { lat: f64, lon: f64, alt_m: f64, quality: f64 }

// AFTER (say your radar emits this instead):
struct MyRecord { latitude: f64, longitude: f64, altitude_ft: f64, track_id: String, conf: f64 }
```

**3. `EDIT 2` — map your record into an `Event`.** This is the one function that
matters: `to_event()`. Call the `EventBuilder` setters that fit your data. The
entity type is the one the operator registered for you; add `.attribute(k, v)`
**only** for attributes that entity type's ontology schema defines (else Core
rejects with `UnknownAttribute`):

```rust
fn to_event(source_id: &str, r: &MyRecord) -> Result<Event, BuildError> {
    EventBuilder::new(source_id, "mim:aircraft")   // <- your assigned entity type
        .new_id()
        .now()
        .location(r.latitude, r.longitude, r.altitude_ft * 0.3048)  // normalise ft → m
        .confidence(r.conf)
        .attribute("track_id", &r.track_id)         // only if the ontology defines it
        .build()
}
```

**4. Swap the feed reader.** The template reads newline-delimited JSON from
stdin. Replace that loop ([main.rs:76-83](rust/examples/connector-template/src/main.rs#L76))
with your real source — a TCP socket, a serial port, a file tail, an API poll —
producing one `MyRecord` per iteration. Everything after that line
(canonical-encode → seal → publish) stays exactly as is.

**That's the whole edit.** You do **not** touch: `canonical_bytes()`, `seal()`,
key loading, the NATS publish, or the subject derivation — those are the SDK and
the boilerplate. If `to_event(...).build()` returns `Ok`, the event is canonical
and correctly signed.

**Where the edit points live per language:**

| Language | Copy this | What you edit |
|----------|-----------|---------------|
| **Rust** | [rust/examples/connector-template/](rust/examples/connector-template/) | `MyRecord` struct (`EDIT 1`) + `to_event()` (`EDIT 2`) + the stdin loop |
| **Python** | [python/examples/connector_template.py](python/examples/connector_template.py) | the one `to_event()` function (marked `EDIT`) + the stdin loop |
| **Go** | [go/examples/synthetic-radar/](go/examples/synthetic-radar/) | the mapping in `main.go` (build the `Event` from your record) + the source loop |
| **C++** | [cpp/examples/first_connector.cpp](cpp/examples/first_connector.cpp) / [synthetic_radar.cpp](cpp/examples/synthetic_radar.cpp) | the `normalize()` / event-build code + the source loop |

(Rust and Python ship dedicated copy-me templates with `EDIT` markers; Go and C++
vendors start from the matching example and edit the equivalent build block.)

**5. Generate your key and declare your profile** — once. The seal/key mechanics
are §6–§7 below; the exact commands (`scripts/gen-connector-key.sh`, then build a
`ConnectorProfile` and send its JSON to your operator) are in
[ONBOARDING.md §6–§7](ONBOARDING.md). **6. Run it** — `--dry-run` first to eyeball
the sealed output with no infra, then point it at NATS.

---

## 5. Step 2 deep-dive — canonical encoding (why the bytes are identical everywhere)

"Canonical" means: **given the same event, every correct implementation produces
the exact same bytes.** This is the foundation of the whole trust model — if the
bytes weren't deterministic, you couldn't sign them and have someone else verify.

The canonical bytes are simply the **deterministic protobuf encoding** of the
`Event` ([canonical.rs](rust/ajar-connector/src/canonical.rs)). Protobuf is a
good fit because:

- Field order in the wire format is determined by field *number*, not by source
  order.
- proto3 omits fields at their default value (empty string, `0`, `0.0`, empty
  list) — so the encoding is fully determined by the values.
- The contract has **no map fields** (maps are the one proto construct with
  non-deterministic ordering), so the encoding is unambiguous.

That leaves exactly one thing a human could get wrong: **the order of the
`attributes` list.** Protobuf will faithfully encode whatever order you give it,
so two events with the same attributes in different order would produce different
bytes. The contract resolves this by *requiring* attributes sorted by key with
unique keys.

This is where `EventBuilder` earns its keep. At `build()`
([builder.rs:160-172](rust/ajar-connector/src/builder.rs#L160)) it:

1. sorts attributes by key (stable sort),
2. walks adjacent pairs and rejects any duplicate key (`DuplicateAttributeKey`),
3. enforces required fields (`id`, `timestamp`, `source_id`, `entity_type`),
4. enforces limits (≤128 attributes, ≤64 policy tags),
5. enforces `confidence ∈ [0.0, 1.0]`,
6. enforces entity-type namespacing,
7. stamps `schema_version = "v1"` and leaves `received_at` empty.

`canonical_bytes()` then *trusts* that invariant and does not re-sort — the
trust boundary is explicit. The practical upshot: **if `build()` returns `Ok`,
the event is canonical and Core will not reject it on shape.** You essentially
cannot emit a malformed event by accident.

---

## 6. Step 3 deep-dive — the seal envelope (the signature)

A "sealed event" on the wire is dead simple
([seal.rs](rust/ajar-connector/src/seal.rs)):

```
  sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
           └────────────── 64-byte detached signature ─────────────┘
  ┌──────────────────────────┬───────────────────────────────────────┐
  │  64 bytes: Ed25519 sig    │  N bytes: the canonical protobuf event │
  └──────────────────────────┴───────────────────────────────────────┘
```

- The signature is **detached** and **prefixed**. The first 64 bytes are the
  Ed25519 signature over the canonical bytes; everything after is the event
  itself.
- Ed25519 signatures are **deterministic** (RFC 8032): signing the same bytes
  with the same key always yields the same signature. So the *entire* sealed
  envelope is reproducible — which is exactly what the conformance gate checks.

On the other side, Core does the obvious inverse: split at byte 64, verify the
signature over the remainder using your **registered public key**, and if it
checks out, decode the canonical suffix back into an `Event`. A bad or
unregistered key → rejected before any policy or ontology logic runs.

**Key handling.** Each connector has its own Ed25519 keypair. You generate it
once ([scripts/gen-connector-key.sh](scripts/gen-connector-key.sh)):

- the **private seed** (32 bytes) stays with your connector — a secret store, an
  HSM, or a locked-down file. `seal()` takes it by reference and never stores,
  logs, or serializes it.
- the **public key** (32 bytes) you send to the operator to register against your
  `source_id`.

The repo's examples use published **test seeds** (`0x47…` for golden vectors,
`0x03…` for the local demo). Those are for reproducibility only — never sign
production events with them.

---

## 7. The connector profile — your registration declaration

Before events flow, the operator needs to know who you are and what you're
allowed to emit. That's the **connector profile**
([profile.rs](rust/ajar-connector/src/profile.rs)) — a small JSON declaration you
build with the SDK and hand to your operator:

```json
{
  "source_id": "acme-radar-1",
  "allowed_entity_types": ["mim:aircraft"],
  "max_payload_bytes": 65536,
  "rate_capacity": 200,
  "rate_refill_per_sec": 20.0,
  "verifying_key_hex": "e28a89..."
}
```

- `verifying_key_hex` is your **public** key as lowercase hex — this is the half
  of the keypair Core uses to verify your seals.
- `allowed_entity_types`, `max_payload_bytes`, and the `rate_*` fields are a
  token-bucket rate limit — they declare your intended envelope so the operator
  can set policy.

Note the profile is a *declaration*, not policy. The SDK just lets you state it
correctly and serialize it deterministically; Core decides what to enforce.

---

## 8. What Core does on the other side (the three gates)

You don't run Core, but knowing its checks tells you exactly what your events
must satisfy. In order:

1. **Signature.** Split the envelope, verify the 64-byte Ed25519 signature over
   the canonical bytes using the public key registered for this `source_id`.
   Wrong/unregistered key, or `source_id` mismatch → **rejected**.
2. **Policy.** Is this `source_id` allowed to emit this `entity_type` with these
   `policy_tags`? Within its rate limit? → else **rejected**.
3. **Ontology.** Does `entity_type` exist in Core's ontology, and do the
   `attributes` match its signed schema? An attribute the schema doesn't define
   → **rejected as `UnknownAttribute`**. An unknown type → **rejected**.

Accepted events land in Postgres and an audit log, ordered by Core's
`received_at` + ingest sequence.

This is why the [ONBOARDING.md §4](ONBOARDING.md#L210) "agree the data contract
first" warning matters: if your `entity_type` or an attribute isn't in Core's
ontology yet, gate 3 rejects you — and that's a change on the *operator's* side,
not something you can fix in the connector.

---

## 9. How trust is established across four languages with no shared code

This is the cleverest part of the system and worth understanding fully.

The SDKs (Rust, Go, Python, C++) share **no runtime code**. They could each have
subtle encoding bugs. So how does a vendor *know* their Go connector produces
bytes that Core (which validates against a Rust-generated reference) will accept?

**Golden vectors.** [vendor/contract/](vendor/contract/) ships:

- `corpus/*.json` — six fixture events (`aircraft_with_attrs`, `drone_minimal`,
  `vessel_with_geo`, plus three edge cases: `edge_origin_location`,
  `edge_unicode_attrs`, `edge_zero_confidence`).
- `vectors.json` — for each fixture, the expected `canonicalSha256` (SHA-256 of
  the canonical bytes) and `sealedSha256` (SHA-256 of the sealed envelope),
  produced by Core itself, signed with a published test seed.

Each language ships a **conformance gate** that, for every fixture:

1. loads the corpus event,
2. produces canonical bytes and hashes them → must equal `canonicalSha256`,
3. seals with the test seed and hashes that → must equal `sealedSha256`.

If a language's encoder or signer is off by a single byte, the hash differs and
the gate fails. Passing it is **proof of byte-compatibility** — your build of the
SDK reproduces the exact bytes Core accepts. Run it before going live:

```bash
cd rust && cargo test -p conformance --test golden_vectors   # Rust
cd go   && go test ./conformance/ -count=1                    # Go
cd python && PYTHONPATH=. python conformance/golden_vectors.py # Python
ctest --test-dir cpp/build                                    # C++
```

The vectors are the contract made executable. You don't trust the SDK authors;
you trust the hashes.

---

## 10. Keeping the contract honest — supply chain

The contract files are *vendored* (copied) from the private Ajar core repo, not
authored here. That copy could drift. Two mechanisms keep it honest:

- **Provenance.** [vendor/contract/PROVENANCE.md](vendor/contract/PROVENANCE.md)
  and `CONTRACT_VERSION` record the exact core commit the files came from
  (`da5094b`, vendored 2026-06-12) and forbid editing them locally.
- **Divergence check.** CI runs [scripts/check-contract.sh](scripts/check-contract.sh),
  which SHA-256-hashes every vendored file and compares against
  `scripts/contract.sha256`. If anyone edits `event.proto`, `vectors.json`, or a
  corpus fixture without re-blessing, CI fails. Re-vendoring is a deliberate act:
  copy from core, regenerate the hashes, bump `CONTRACT_VERSION`, and the
  conformance gate re-validates the new bytes.

So the chain is: **core defines the contract → it's vendored with a recorded
commit → its hashes are pinned in CI → every SDK proves it reproduces the
vectors.** No silent drift at any link.

---

## 11. How it deploys (and how the key stays safe)

The connector is a single process/container you run at the edge. The repo ships
a reference Docker image and a Helm chart ([deploy/](deploy/)).

- **Image** — distroless, non-root (`USER nonroot`, UID 65532), read-only root
  filesystem, all capabilities dropped, `seccomp: RuntimeDefault`.
- **Key injection** — the signing seed is mounted into the container as a
  **read-only file** from a Kubernetes Secret; an env var points to the *path*,
  not the value. The connector reads 32 bytes from that file. The seed never
  appears in env, logs, or shell history. (The Helm template *fails to render* if
  no image or key is configured — fail-fast, not fail-open.)
- **Transport** — mTLS to NATS: the templates read `AJAR_TLS_CA` /
  `AJAR_TLS_CERT` / `AJAR_TLS_KEY` (client-cert CN = `source_id`) and present a
  client certificate; unset → plaintext for local dev. The chart mounts these
  from a Secret at `/etc/ajar/tls`. An optional egress-only NetworkPolicy
  restricts the pod to NATS + DNS.
- **Resilience + health** — the templates skip bad records and survive NATS blips
  (non-fatal publish, auto-reconnect) rather than crashing. Set
  `AJAR_HEALTH_ADDR` to expose `GET /healthz` and `GET /metrics`; the chart wires
  it and adds liveness/readiness probes by default.

The three deployment topologies (central Core, disconnected outpost, edge
gateway) are described in [ONBOARDING.md §2](ONBOARDING.md#L68). The connector
code is **identical** in all three — only *where NATS and Core run* changes.

---

## 12. End-to-end, one more time

```
 1. Operator assigns you a source_id, registers your public key + entity types,
    gives you a NATS endpoint.                                  (one-time setup)
       │
 2. Your connector reads a native record.                      (your feed)
       │
 3. EventBuilder maps it → validates → canonical Event.        (SDK, fail-closed)
       │
 4. canonical_bytes() → deterministic protobuf.                (SDK)
       │
 5. seal() → 64-byte Ed25519 sig ++ canonical bytes.           (SDK, your key)
       │
 6. publish to ajar.ingest.<source_id>.                        (NATS client)
       │
       ▼
 7. NATS delivers to Core.
       │
 8. Core: verify signature → check policy → validate ontology. (three gates)
       │
       ▼
 9. Accepted → Postgres + audit log, ordered by Core's clock.
```

Steps 3–6 are this SDK. Step 2 is the ~15 lines you write. Steps 1 and 7–9 are
the operator's side. The conformance gate (§9) is your proof that steps 3–6
produce exactly what step 8 will accept.

---

## Where to look in the code

| Concept | File |
|---------|------|
| The contract (source of truth) | [vendor/contract/event.proto](vendor/contract/event.proto) |
| Build + validate an event | [rust/ajar-connector/src/builder.rs](rust/ajar-connector/src/builder.rs) |
| Canonical encoding | [rust/ajar-connector/src/canonical.rs](rust/ajar-connector/src/canonical.rs) |
| The seal envelope | [rust/ajar-connector/src/seal.rs](rust/ajar-connector/src/seal.rs) |
| The connector profile | [rust/ajar-connector/src/profile.rs](rust/ajar-connector/src/profile.rs) |
| Public API surface | [rust/ajar-connector/src/lib.rs](rust/ajar-connector/src/lib.rs) |
| Golden vectors + conformance | [vendor/contract/vectors.json](vendor/contract/vectors.json), `*/conformance/` |
| Contract divergence check | [scripts/check-contract.sh](scripts/check-contract.sh) |
| Copy-me templates | [rust/examples/connector-template/](rust/examples/connector-template/), [python/examples/connector_template.py](python/examples/connector_template.py) |
| Deployment | [deploy/helm/connector/](deploy/helm/connector/), [deploy/docker/](deploy/docker/) |

For "what do I type to get started," go to [ONBOARDING.md](ONBOARDING.md).
</content>
</invoke>
