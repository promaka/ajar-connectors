<!-- SPDX-License-Identifier: Apache-2.0 -->
# Connector onboarding guide

This guide is for a **vendor** building a connector that feeds data into Ajar.
A connector has one job: turn your system's native data into Ajar's canonical,
**signed** event and publish it. The SDK does the hard parts (canonical
encoding, signing); you write the small piece that maps *your* data.

- [1. How data flows](#1-how-data-flows)
- [2. What you build](#2-what-you-build)
- [3. Before you start: what Ajar gives you](#3-before-you-start-what-ajar-gives-you)
- [4. Build it](#4-build-it)
- [5. Generate your signing key](#5-generate-your-signing-key)
- [6. Declare your profile](#6-declare-your-profile)
- [7. Run it](#7-run-it)
- [8. Verify you're byte-compatible](#8-verify-youre-byte-compatible)
- [9. Troubleshooting](#9-troubleshooting)

---

## 1. How data flows

```
  your system            your connector (this SDK)                 Ajar Core
 ┌───────────┐   native  ┌───────────────────────────┐  sealed   ┌──────────────────────────┐
 │ radar /   │  record   │ 1. normalize → Event       │  bytes    │ verify signature         │
 │ AIS / API │ ────────▶ │ 2. seal (Ed25519 sign)     │ ────────▶ │ check policy             │ ─▶ accepted
 │ /sensor   │           │ 3. publish to NATS         │   NATS    │ validate against ontology│    ├─▶ Postgres
 └───────────┘           └───────────────────────────┘  subject  └──────────────────────────┘    └─▶ audit log
                                                      ajar.ingest.<source_id>
```

What each Core stage checks (this is what your events must satisfy):

1. **Signature** — the event is sealed with your connector's private key; Core
   verifies it against the public key you registered. Bad/unregistered key →
   rejected.
2. **Policy** — your `source_id`, `entity_type`, and markings are allowed.
3. **Ontology** — the `entity_type` exists and any `attributes` match its
   schema. An attribute the schema doesn't know → rejected as `UnknownAttribute`.

A **sealed event** on the wire is simply:

```
  [ 64-byte Ed25519 signature ][ canonical protobuf bytes ]
```

## 2. What you build

The whole connector is a loop of three steps. The SDK gives you steps 2–3; you
write step 1 — "map one of my records into an `Event`":

```
your record  →  build Event  →  seal  →  publish
                (EventBuilder) (seal)   (NATS client)
```

A complete minimal connector (Rust) is ~30–60 lines. Here is the core of it:

```rust
use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

// 1. NORMALIZE: map one native record into a canonical Event.
//    This is the only Ajar-specific logic you write (~15 lines).
fn to_event(source_id: &str, r: &MyRecord) -> Result<ajar_connector::Event, ajar_connector::BuildError> {
    EventBuilder::new(source_id, "mim:aircraft")  // the entity type Ajar assigned you
        .new_id()                                 // unique UUIDv7 id
        .now()                                    // observation time (RFC 3339)
        .location(r.lat, r.lon, r.altitude_m)     // aircraft need a position
        .confidence(r.quality)                    // 0.0..=1.0
        .policy_tag("class:secret")               // markings, if any
        // .attribute("k", "v")  // ONLY if your entity type's ontology schema has them
        .build()                                  // validates; can't emit a bad event
}

// 2 + 3. SEAL and PUBLISH (copied from the example, unchanged):
let canonical = canonical_bytes(&event);
let sealed = seal(&canonical, &signing_key);          // 64-byte sig ++ canonical
client.publish(subject.clone(), sealed.into()).await?; // to ajar.ingest.<source_id>
```

The easiest way to start is to **copy a reference connector** and replace the
data source with yours:

- Rust: [rust/examples/synthetic-radar](rust/examples/synthetic-radar/) (streams to NATS)
- Go: [go/examples/synthetic-radar](go/examples/synthetic-radar/)
- C++: [cpp/examples/synthetic_radar.cpp](cpp/examples/synthetic_radar.cpp)
- Parsing a real native format end-to-end: the CoT example
  ([rust/examples/cot-connector](rust/examples/cot-connector/)) shows
  `native bytes → Event`.

Swap the synthetic track generator for your feed reader, keep the seal/publish
loop as-is.

## 3. Before you start: what Ajar gives you

Ask your Ajar operator for these four things. The first three are a one-time
setup on their side:

| You receive | What it is |
|-------------|-----------|
| a **`source_id`** | your connector's stable identity, e.g. `acme-radar-1` |
| **entity type(s) registered** | the `mim:<type>` / `x:<vendor>:<type>` (and any attribute schema) you'll emit must exist in Core's ontology |
| **your public key registered** | you generate a key (§5) and send the **public** half; Ajar registers it against your `source_id` |
| **ingest endpoint + creds** | the NATS server address (and credentials/TLS) to publish to |

> Agree the **data contract first**: which entity type(s) you emit and which
> attributes (with units). If your entity type or an attribute isn't in Core's
> ontology yet, events using it are rejected — that has to be added on the Ajar
> side before you go live.

## 4. Build it

Pick a language and add the SDK. (Until packages are published, depend on this
repo via git.)

**Rust** — in your `Cargo.toml`:
```toml
[dependencies]
ajar-connector = { git = "https://github.com/promaka/ajar-connectors", branch = "main" }
```

**Go**:
```bash
go get github.com/promaka/ajar-connectors/go/ajarconnector
```

**C++** — use the CMake project under [cpp/](cpp/); link `ajar_connector`.

Then implement your `to_event` mapping (§2) and reuse the seal+publish loop from
the matching example.

## 5. Generate your signing key

Each connector has its **own** Ed25519 key. Generate it once and keep the
private half secret (a secrets manager, an HSM, a file with locked-down perms —
never in source control).

```bash
# Generate an Ed25519 key:
openssl genpkey -algorithm ed25519 -out connector.key

# The 32-byte PRIVATE seed your connector seals with (keep secret):
openssl pkey -in connector.key -outform DER | tail -c 32 | xxd -p -c 64
#   -> e.g. 9f3c...   (load these 32 bytes into SigningKey::from_bytes)

# The 32-byte PUBLIC key you send to Ajar to register:
openssl pkey -in connector.key -pubout -outform DER | tail -c 32 | xxd -p -c 64
#   -> e.g. e28a...   (this is verifying_key_hex in your profile)
```

Load the seed in the connector (read it from your secret store, not a literal):

```rust
let seed: [u8; 32] = load_seed_bytes();        // 32 bytes from your secret store
let signing_key = SigningKey::from_bytes(&seed);
```

> The repo's examples use **dev-only test seeds** (32 bytes of `0x03` for the
> local demo, `0x47` for the golden vectors). Never sign production events with
> those.

## 6. Declare your profile

Your **connector profile** is the declaration Ajar registers for you. Build it
with the SDK and hand the JSON to your operator:

```rust
use ajar_connector::ConnectorProfile;

let profile = ConnectorProfile::new("acme-radar-1", signing_key.verifying_key())
    .allow_entity_type("mim:aircraft")
    .max_payload_bytes(64 * 1024)
    .rate_limit(200, 20.0);     // burst capacity, refill/sec
println!("{}", profile.to_json_pretty());
```

produces exactly what Ajar needs:

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

## 7. Run it

Three stages, each lower-risk than the next:

**a) Offline — no infrastructure.** Build + seal + print events; check your
mapping looks right:
```bash
cd rust/examples
cargo run -p synthetic-radar -- --dry-run
```

**b) Against a local Ajar.** Point at a local NATS/Core and watch events flow
`connector → NATS → Core → accepted → Postgres + audit`:
```bash
NATS_URL=nats://127.0.0.1:4222 \
AJAR_SOURCE_ID=acme-radar-1 \
cargo run -p synthetic-radar
```
(The subject is derived automatically: `ajar.ingest.<source_id>`.)

**c) Production.** Same binary, pointed at the real ingest endpoint with your
credentials, signing with your real key.

## 8. Verify you're byte-compatible

Before going live, run the **conformance gate** in your language. It proves your
build of the SDK reproduces the exact bytes Ajar accepts — if it's green, your
events are byte-compatible.

```bash
# Rust
cd rust && cargo test -p conformance --test golden_vectors

# Go
cd go && go test ./conformance/ -count=1

# C++
ctest --test-dir cpp/build
```

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Event rejected: **signature invalid** | public key not registered, or signing with the wrong seed, or `source_id` ≠ registered | confirm the registered `verifying_key_hex` matches your key; check `AJAR_SOURCE_ID` |
| Event rejected: **`UnknownAttribute`** | you set an attribute the entity type's ontology schema doesn't define | remove it, or have Ajar add the attribute to the ontology |
| Event rejected: **unknown entity type** | the `entity_type` isn't registered in Core's ontology | use a registered type, or get it added |
| Builder returns **`UnnamespacedEntityType`** | entity type isn't `mim:<type>` or `x:<vendor>:<type>` | namespace it (or `allow_unnamespaced_entity_type()` only for migration) |
| Builder returns **`DuplicateAttributeKey`** / **`TooManyAttributes`** | violates canonical rules | the builder is protecting you — fix the input |
| Nothing arrives, no error | wrong subject or `source_id` | subject must be `ajar.ingest.<source_id>` with the assigned `source_id` |

> You generally **can't** emit a non-canonical event by accident: `EventBuilder`
> sorts attributes, rejects duplicate keys, enforces required fields and limits,
> and leaves `received_at` empty (Ajar stamps its own clock). If `build()`
> succeeds, the shape is valid.

---

Questions or a new entity type / attribute schema needed in the ontology? Talk
to your Ajar operator — that's the one part that lives on the Core side, not in
this SDK.
