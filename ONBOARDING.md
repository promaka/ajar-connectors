<!-- SPDX-License-Identifier: Apache-2.0 -->
# Connector onboarding guide

This guide is for a **vendor** building a connector that feeds data into Ajar.
A connector has one job: turn your system's native data into Ajar's canonical,
**signed** event and publish it. The SDK does the hard parts (canonical
encoding, signing); you write the small piece that maps *your* data.

> ## ⚡ Quickstart — the whole job is two edits
>
> See a real signed event **right now** — no key, no NATS, no feed:
> ```bash
> # Rust:
> cd rust/examples && echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
>   | cargo run -p connector-template -- --dry-run
>
> # …or Python:
> cd python && echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
>   | PYTHONPATH=. python examples/connector_template.py --dry-run
> ```
> Then make it yours: copy the `connector-template` for your language and edit the
> block(s) marked **`EDIT`** (describe your record + map it to an event) — about
> 15 lines. Generate a key with `scripts/gen-connector-key.sh`, set three env
> vars, run. That's the entire integration. The sections below explain the *why*.
> Templates: [Rust](rust/examples/connector-template/) · [Python](python/examples/connector_template.py)
> (Go and C++ vendors copy [`go/examples/synthetic-radar`](go/examples/synthetic-radar/) / [`cpp/examples/synthetic_radar.cpp`](cpp/examples/synthetic_radar.cpp)).

- [1. How data flows](#1-how-data-flows)
- [2. Where everything runs (deployment & topology)](#2-where-everything-runs-deployment--topology)
- [3. What you build](#3-what-you-build)
- [4. Before you start: what Ajar gives you](#4-before-you-start-what-ajar-gives-you)
- [5. Build it](#5-build-it)
- [6. Generate your signing key](#6-generate-your-signing-key)
- [7. Declare your profile](#7-declare-your-profile)
- [8. Run it](#8-run-it)
- [9. Verify you're byte-compatible](#9-verify-youre-byte-compatible)
- [10. Troubleshooting](#10-troubleshooting)

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

## 2. Where everything runs (deployment & topology)

**The one idea:** the connector and Ajar Core **never talk to each other
directly**. They both connect to a **NATS server** (a message bus) in the
middle. The connector *publishes* sealed events to it; Core *subscribes* and
pulls them off.

```
   connector  ──publish──▶  ┌─────────┐  ──deliver──▶  Ajar Core
   (vendor)                 │  NATS   │                (operator)
                            │ broker  │
                            └─────────┘
        ▲ each side opens an outbound TCP connection to NATS ▲
```

Trust lives in the **signature, not the pipe**: the connector signs each event,
Core verifies it against your registered public key. So events can cross an
untrusted, lossy, or relayed link and Core still knows they're authentic and
unmodified. The connector doesn't even need to know *where* Core is — only where
NATS is.

### Who runs what

| | Builds it | Runs it | Holds |
|---|---|---|---|
| **Vendor** | the connector (their code + this SDK) | the connector process, at/near the data source | its **private** signing key |
| **Operator** | nothing (runs Ajar) | NATS + Ajar Core + Postgres + audit | the connector's **public** key (registered) |

So the vendor's connector runs **at the edge** (with the sensor); the operator
runs Ajar Core **where governance + storage live** (a C2/hub, or forward in an
outpost). NATS sits wherever you decide the two should meet.

### Default picture

```
   EDGE NODE (with the sensor)                         C2 / HUB
 ┌─────────────────────────────┐                ┌──────────────────────────┐
 │ sensor → connector          │  sealed events │  NATS  →  Ajar Core       │
 │          (vendor code + SDK)│ ──────────────▶│           verify→policy→  │
 │          signs each event   │  tactical/VPN  │           ontology→accept │
 └─────────────────────────────┘     link       │              ├─ Postgres  │
                                                 │              └─ audit log │
                                                 └──────────────────────────┘
```

### The three common scenarios

The connector code is **identical** in all three — only *where NATS and Core
run* changes.

**1. Central Core (most common).** Edge connectors publish to one NATS at C2;
one Core verifies and stores centrally.

```
 edge A ┐
 edge B ┼──▶ NATS @ C2 ──▶ Core ──▶ Postgres + audit
 edge C ┘
```

**2. Disconnected outpost (works when cut off).** An outpost runs its **own**
NATS + Core locally (the air-gapped systemd/Podman bundle). Connectors publish
locally and the outpost accepts/stores locally with no link home; it forwards
upstream to C2 when a link returns.

```
 OUTPOST (own NATS + Core, fully local)
 connector ──▶ NATS ──▶ Core ──▶ local Postgres + audit
                                   └····· syncs to C2 when a link is available ····▶
```

**3. Edge gateway.** Many sensors funnel through a small local NATS on the edge
node, which relays to C2's NATS when connected (a NATS "leaf"); buffers during
outages.

```
 sensors ──▶ NATS (edge leaf) ~~relays when up~~▶ NATS @ C2 ──▶ Core
```

### Where is NATS in the code?

NATS-the-**server** is **not something anyone writes** — it's a third-party
binary (`nats-server`, from nats.io) that your *deployment* runs as a process or
container (the systemd + Podman bundle). You won't find its source in either
repo. What you find is **client** code:

- **In this connector repo (`ajar-connectors`):** only in the *examples* (a NATS
  client publishing) — the SDK crate itself has **no** NATS dependency and is
  transport-free.
- **In the core repo (`promaka/ajar`):** a NATS *client* that **subscribes** to
  `ajar.ingest.>` and the deployment manifests that launch the `nats-server`
  container. (Core uses `async-nats` as a client; it does not embed the server.)

So: nobody codes NATS — you **run** a `nats-server`, the connector publishes to
it, and Core subscribes to it.

## 3. What you build

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

## 4. Before you start: what Ajar gives you

### How onboarding actually works

There is **no sign-up portal** — and you don't need one. Building the connector
is entirely self-serve from this repository: clone it, copy a template, edit the
~15-line mapping, build, and run it in `--dry-run` to see signed events
immediately. Nothing below blocks you from *building*.

The one thing that isn't self-serve is getting your events **accepted**. Your
connector signs with a key only you hold; for Ajar Core to verify and store your
events, the **operator** (whoever runs Ajar Core — typically us) has to register
your identity on their side first. That's a one-time **handshake**, not an
account:

> **You send the operator:** your chosen `source_id`, your connector
> **profile** JSON (§7 — it contains your *public* key and the entity types you
> intend to emit), and the entity type(s) + any attribute schema you need.
>
> **The operator sends back:** confirmation your key + types are registered, plus
> the **NATS ingest endpoint and credentials** to publish to.

**Who is "the operator"?** Whoever runs Ajar Core for you — the team that pointed
you at this repo. The contact and the exact entity types are in the **Connector
Brief** they send you (template: [CONNECTOR_BRIEF.md](CONNECTOR_BRIEF.md)); if you
don't have one, ask them for it.

Once that handshake is done, the same connector binary you already built and
tested goes straight to production (§8c).

### The four things you end up with

The handshake leaves you with these four things. The first three are a one-time
setup on the operator's side:

| You receive | What it is |
|-------------|-----------|
| a **`source_id`** | your connector's stable identity, e.g. `acme-radar-1` |
| **entity type(s) registered** | the `mim:<type>` / `x:<vendor>:<type>` (and any attribute schema) you'll emit must exist in Core's ontology |
| **your public key registered** | you generate a key (§6) and send the **public** half; Ajar registers it against your `source_id` |
| **ingest endpoint + creds** | the NATS server address (and credentials/TLS) to publish to |

> Agree the **data contract first**: which entity type(s) you emit and which
> attributes (with units). If your entity type or an attribute isn't in Core's
> ontology yet, events using it are rejected — that has to be added on the Ajar
> side before you go live.

## 5. Build it

Pick a language and add the SDK. (Until packages are published, depend on this
repo via git.) **Pin the released tag `v0.1.0`, not a branch** — that's what makes
your build reproducible and means you're never forced to upgrade (see
[COMPATIBILITY.md](COMPATIBILITY.md)).

**Rust** — in your `Cargo.toml`:
```toml
[dependencies]
ajar-connector = { git = "https://github.com/promaka/ajar-connectors", tag = "v0.1.0" }
```

**Go**:
```bash
go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.1.0
```

**Python** — install from the repo (until it's published to PyPI):
```bash
# straight from GitHub, pinned to the tag:
pip install "git+https://github.com/promaka/ajar-connectors.git@v0.1.0#subdirectory=python"
# …or, if you've cloned the repo, an editable install:
cd python && pip install -e .
```

**C++** — build the CMake project, then link `ajar_connector` into your own
build. See [cpp/README.md](cpp/README.md) for the full integration guide
(including `find_package`); the quick build is:
```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build -j
```

Then implement your `to_event` mapping (§3) and reuse the seal+publish loop from
the matching example.

## 6. Generate your signing key

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

## 7. Declare your profile

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

## 8. Run it

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

### Production behaviour (built into the templates)

The reference templates are written to survive real feeds and a flaky link — you
don't need to add this:

- **Bad input is skipped, not fatal.** A malformed or un-mappable record is
  logged and skipped; one bad record can't take the connector down.
- **Publish errors are non-fatal.** A NATS blip is logged and the connector keeps
  going; the client retries the initial connection and auto-reconnects after a
  drop.
- **Health + metrics.** Set `AJAR_HEALTH_ADDR=0.0.0.0:9090` to expose
  `GET /healthz` (liveness) and `GET /metrics` (Prometheus counters: published /
  skipped / publish_errors). The Helm chart wires this and adds k8s
  liveness/readiness probes by default (`health.enabled=true`).
- **mTLS to NATS.** A production NATS authenticates connectors with a client
  certificate. Set all three and the connector presents it; leave them unset for
  local plaintext dev:
  - `AJAR_TLS_CA` — the CA (PEM) that signs the NATS server cert,
  - `AJAR_TLS_CERT` — your client certificate (its CN is your `source_id`),
  - `AJAR_TLS_KEY` — your client private key.

  Your operator issues the cert/key alongside your `source_id`; use a `tls://`
  endpoint. The Helm chart mounts these from a Secret at `/etc/ajar/tls` and sets
  the env vars for you (`tls.existingSecret`).

## 9. Verify you're byte-compatible

Before going live, run the **conformance gate** in your language. It proves your
build of the SDK reproduces the exact bytes Ajar accepts — if it's green, your
events are byte-compatible.

```bash
# Rust
cd rust && cargo test -p conformance --test golden_vectors

# Go
cd go && go test ./conformance/ -count=1

# Python
cd python && PYTHONPATH=. python conformance/golden_vectors.py

# C++
ctest --test-dir cpp/build
```

## 10. Troubleshooting

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
