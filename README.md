<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connectors

The vendor-facing SDK for building **connectors** to [Ajar](https://github.com/promaka/ajar),
the sovereign defence integration & governance plane.

A connector turns a vendor or legacy system's native data into Ajar's canonical,
signed **event** (inbound), and/or renders governed events into a target
system's format (outbound). This repo is **standalone** and **Apache-2.0** — it
never depends on the private Ajar core. It earns trust by reproducing the
*golden byte-vectors* that core accepts: byte-for-byte compatibility is the
acceptance test, not a promise.

```
native bytes ──▶ Connector::normalize ──▶ Event ──▶ canonical_bytes ──▶ seal ──▶ Ajar
 (CoT, CSV,                              (canonical            (deterministic    (sig ++
  vendor frame)                           protobuf)             protobuf)         bytes)
```

> **Building a connector?** Start with the **[connector onboarding guide](ONBOARDING.md)** —
> data flow, what to build, key generation, profile declaration, running it, and
> troubleshooting.

## Status

| Language | SDK | Conformance gate |
|----------|-----|------------------|
| Rust     | ✅ `rust/ajar-connector` | ✅ reproduces all golden vectors |
| Go       | ✅ `go/ajarconnector` | ✅ reproduces all golden vectors (same `vectors.json`) |
| C++ (desktop) | ✅ `cpp/` (protoc-C++) | ✅ reproduces all golden vectors (same `vectors.json`) |
| C++ (embedded) | ✅ `cpp/embedded/` (nanopb, no-heap) | ✅ reproduces all golden vectors (same `vectors.json`) |
| Python   | ✅ `python/ajar_connector` | ✅ reproduces all golden vectors (same `vectors.json`) |

All language SDKs assert against the **same** [vendor/contract/vectors.json](vendor/contract/vectors.json)
and produce byte-identical canonical bytes for every fixture — that
cross-language identity is the proof. **Five independent protobuf encoders** (Rust
prost, Go, libprotobuf, nanopb, and Python protobuf) now agree on every hash. The
C++ builds vendor their crypto (Monocypher Ed25519, no system dependency); the
embedded nanopb build links no protobuf runtime and allocates nothing on the heap
on the encode path — the radar/effector-controller path.

## Write your first connector in 20 lines

```rust
use ajar_connector::{canonical_bytes, seal, ConnectorProfile, Connector, SigningKey};
use cot_connector::CotConnector;

// 1. Normalize native input (here: a Cursor-on-Target message) to a canonical event.
let connector = CotConnector::new("ad-radar-7");
let event = connector.normalize(native_cot_bytes)?;

// 2. Canonicalize and sign with this connector's own Ed25519 key.
let signing_key = SigningKey::from_bytes(&my_persisted_key_bytes);
let canonical = canonical_bytes(&event);
let sealed = seal(&canonical, &signing_key); // 64-byte signature ++ canonical bytes

// 3. Declare the profile Ajar registers for you.
let profile = ConnectorProfile::new("ad-radar-7", signing_key.verifying_key())
    .allow_entity_type("mim:aircraft")
    .rate_limit(200, 20.0);
```

Run the full reference end-to-end (examples are their own workspace under
[rust/examples/](rust/examples/)):

```bash
cd rust/examples
cargo run -p cot-connector --example first_connector
```

Or stream synthetic tracks into a local Ajar Core over NATS and watch the whole
path (`connector → NATS → Core → audit + Postgres`) — see
[examples/synthetic-radar](rust/examples/synthetic-radar/):

```bash
cd rust/examples
cargo run -p synthetic-radar -- --dry-run   # build + seal + print, no infra
cargo run -p synthetic-radar                # publish to a local NATS / Core
```

Or build an event directly with the validating builder:

```rust
use ajar_connector::EventBuilder;

let event = EventBuilder::new("sensor-123", "mim:drone")
    .new_id()                    // UUIDv7, time-ordered
    .now()                       // RFC 3339 observation time
    .confidence(0.98)
    .policy_tag("class:secret")
    .attribute("speed", "110")
    .attribute("heading", "225") // auto-sorted; duplicate keys rejected
    .build()?;                   // required fields + canonical invariants enforced
```

### …or in Go

```go
import "github.com/promaka/ajar-connectors/go/ajarconnector"

event, err := ajarconnector.NewEventBuilder("sensor-123", "mim:drone").
    NewID().Now().
    Confidence(0.98).
    PolicyTag("class:secret").
    Attribute("speed", "110").
    Attribute("heading", "225"). // auto-sorted; duplicate keys rejected
    Build()

canonical, _ := ajarconnector.CanonicalBytes(event)
sealed := ajarconnector.Seal(canonical, signingKey) // crypto/ed25519
```

```bash
# Examples are their own Go module under go/examples:
cd go/examples && go run ./cot/cmd/first_connector
cd go/examples && go run ./synthetic-radar -dry-run   # stream synthetic tracks
```

## The contract & the gate

- The wire contract is vendored verbatim from core into
  [`vendor/contract/`](vendor/contract/) (`event.proto`, golden `vectors.json`,
  and `corpus/*.json` fixtures). It is the **source of truth**; do not edit it
  here — re-vendor when the contract version changes.
- Rust types are **generated** from `event.proto` (via `prost`, with a vendored
  `protoc` so a plain `cargo build` needs nothing installed).
- The acceptance test lives in `rust/conformance`: for every fixture it asserts
  `SHA-256(canonical_bytes) == canonicalSha256` and
  `SHA-256(sealed) == sealedSha256`. **Green = byte-compatible with Ajar.**

```bash
cd rust && cargo test -p conformance --test golden_vectors
```

## Public API (`ajar-connector`)

- Generated `Event` / `GeoPoint` / `Attribute` types.
- `EventBuilder` — auto-sorts & dedups attributes, enforces required fields and
  limits, UUIDv7 / RFC 3339 helpers.
- `canonical_bytes(&Event) -> Vec<u8>` — deterministic protobuf encoding.
- `seal(&[u8], &SigningKey) -> Vec<u8>` — detached Ed25519 signature ++ canonical.
- `ConnectorProfile` — declaration + deterministic JSON serializer.
- `Connector` trait — inbound `normalize(&[u8]) -> Result<Event, _>`.
- `OutboundProfile` trait — `target/slug/version/modeled_fields/lossy_fields/render`,
  with round-trip (`canonical → target → canonical`) conformance.

## The seal envelope

```
sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
         └──────────── 64-byte detached signature ───────────┘
```

Each production connector holds its **own** signing key; Ajar registers the
matching public key in the connector's profile. The seed used by the golden
vectors (32×`0x47`) is a published **TEST** seed — never sign production events
with it.

## Not in scope

The SDK does **not** implement policy, audit, ontology enforcement, correlation,
or the pipeline — that is core's job. It only produces valid signed events,
declares profiles, and translates in/out. It never sees secrets beyond a
connector's own signing key.

## Deploying a connector (Kubernetes)

For clusters at a C2/hub or a forward outpost, a Helm chart packages a connector
as a Deployment — wiring up the signing key (from a Secret), the standard config
(`AJAR_SOURCE_ID`, `NATS_URL`, `AJAR_INGEST_PREFIX`), optional mTLS, and an
optional egress-only-to-NATS NetworkPolicy. A reference image (multi-stage,
distroless non-root) is at [deploy/docker/Dockerfile](deploy/docker/Dockerfile):

```bash
docker build -f deploy/docker/Dockerfile -t registry.you.mil/acme-radar:1.0.0 .
kubectl create secret generic acme-radar-seed --from-file=seed=acme-radar.seed
helm install acme-radar deploy/helm/connector \
  --set image.repository=registry.you.mil/acme-radar --set image.tag=1.0.0 \
  --set connector.sourceId=acme-radar-1 \
  --set connector.natsUrl=nats://ajar-ajar-nats:4222 \
  --set signingSeed.existingSecret=acme-radar-seed
```

It's generic — you bring your connector image; the chart does the wiring, with a
hardened security posture matching Core. The same binary also runs fine as a
plain process or systemd unit at the edge. See
[deploy/helm/connector](deploy/helm/connector/). (The chart deploys a
*connector*; NATS and Ajar Core are operator-side, paired with the Core chart in
`promaka/ajar`.)

## Contributing & license

Apache-2.0 (see [LICENSE](LICENSE)). Every source file carries an SPDX header.
Commits require a [DCO](CONTRIBUTING.md) sign-off (`git commit -s`).
