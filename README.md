<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connectors

[![ci](https://github.com/promaka/ajar-connectors/actions/workflows/ci.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/ci.yml)
[![image](https://github.com/promaka/ajar-connectors/actions/workflows/image.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/image.yml)
[![deploy](https://github.com/promaka/ajar-connectors/actions/workflows/helm.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/helm.yml)

The vendor-facing SDK for building **connectors** to **Ajar**,
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
| Rust     | `rust/ajar-connector` | reproduces all golden vectors |
| Go       | `go/ajarconnector` | reproduces all golden vectors (same `vectors.json`) |
| C++ (desktop) | `cpp/` (protoc-C++) | reproduces all golden vectors (same `vectors.json`) |
| C++ (embedded) | `cpp/embedded/` (nanopb, no-heap) | reproduces all golden vectors (same `vectors.json`) |
| Python   | `python/ajar_connector` | reproduces all golden vectors (same `vectors.json`) |

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

let event = EventBuilder::new("sensor-123", "mim:aircraft")
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

event, err := ajarconnector.NewEventBuilder("sensor-123", "mim:aircraft").
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
- `verify(&[u8], &VerifyingKey) -> Result<&[u8], SealError>` — the inverse: confirms
  the bytes were sealed by the holder of that key and are unaltered, returning the
  canonical event. A recipient can establish provenance with no connector, broker
  or Core present.
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

## Reference connectors

The `rust/examples/` above teach the SDK. Alongside them, `rust/connectors/` holds
**production, standard-format connectors** — one per open wire standard, not per
system, so any kit already speaking that standard connects by config alone. They
share a runtime crate ([`connectors/common`](rust/connectors/common)) — config,
key loading, mTLS NATS, the transport layer, the seal-and-publish loop, health,
graceful shutdown — so a new connector is a format parser (`FrameParser`) plus a
few lines of wiring.

| Connector | Standard | What it feeds | Typical transport |
|-----------|----------|---------------|-------------------|
| [asterix](rust/connectors/asterix) | ASTERIX CAT021 / 048 / 062 | radar + ADS-B + fused air tracks | UDP multicast |
| [adsb](rust/connectors/adsb) | ADS-B (SBS-1 / BaseStation) | cooperative aircraft tracks | TCP client |
| [ais-nmea](rust/connectors/ais-nmea) | AIS over NMEA 0183 | maritime vessel tracks | TCP client / UDP |
| [gmti](rust/connectors/gmti) | STANAG 4607 (NATO GMTI) | ground moving-target detections | file / TCP / UDP |
| [klv](rust/connectors/klv) | STANAG 4609 / MISB ST 0601 (KLV) | FMV platform / sensor metadata | UDP / file |
| [stanag4676](rust/connectors/stanag4676) | STANAG 4676 (NATO ISR Tracking) | fused ISR tracks | TCP / file |
| [mavlink](rust/connectors/mavlink) | MAVLink v1/v2 | small-UAS / drone telemetry | UDP / serial |
| [stanag4586](rust/connectors/stanag4586) | STANAG 4586 (NATO UAS Control) | military UAS telemetry | UDP |
| [tak-cot](rust/connectors/tak-cot) | TAK / Cursor-on-Target | ground/air situational-awareness tracks | UDP multicast / unicast |
| [generic](rust/connectors/generic) | any flat JSON / CSV | the long tail — **no code, just a field mapping** | any of the below |
| [tak-egress](rust/connectors/tak-egress) | TAK / CoT (**egress**) | governed COP tracks OUT to a TAK Server, verbatim | NATS → TLS 8089 |

Each maps a standard's **position reports** (and, where present, identity and
tactical fields) onto Ajar tracks; each connector's README states which message
types/categories it covers. The **generic** connector needs no Rust at all — a
`[mapping]` block in its config turns a JSON/CSV source into events. Extending
coverage is additive.

**Which connector for your kit?** See **[CONNECTORS.md](CONNECTORS.md)** — a
catalogue of what each connector is for and the real systems that speak each format
(radars, AIS transponders, autopilots, UAS ground stations, TAK devices, …).

### Transport is orthogonal to protocol

A connector never hard-codes *how bytes arrive*. The protocol (parsing) and the
transport (delivery) are separate, so any connector runs on any method by config:

| `kind` | Method | Notes |
|--------|--------|-------|
| `udp-multicast`, `udp` | UDP datagrams | one packet per frame (SA broadcast) |
| `tcp-client` | TCP stream (dial out) | `framing = "line"` or `"length-delimited"`, auto-reconnect |
| `tcp-server` | TCP listen | sources that push to a configured address; multiple pushers |
| `http-server` | HTTP(S) listen (webhooks) | sources that only POST to a URL; optional TLS and client certs; refuses with 503 when saturated so the sender retries |
| `file` | tail a file | follows appends, handles rotation |
| `dir` | watch a drop directory | batch file drops (SFTP exports); reads files once settled |
| `exec` | run a CLI tool | reads its stdout; wraps any vendor binary |
| `stdin` | pipe | `producer \| ajar-<connector>` |
| `serial` | RS-232/422/485 | needs the `serial` feature (NMEA sensors) |
| `mqtt` | subscribe a topic | needs the `mqtt` feature (IoT buses) |
| `rest-poll` | HTTP GET on interval | needs the `rest-poll` feature (pull-only APIs) |
| `ws-client` | WebSocket, connect out | needs the `websocket` feature; hosted live feeds, subscription message and auth headers supported |

DDS is reached through an external gateway that re-publishes onto one of these
(usually `udp-multicast` or `mqtt`), not as a native kind. Full onboarding —
including registering the connector with the sovereign's control plane — is in
[ONBOARDING.md](ONBOARDING.md).

Build and test them on their own (they resolve their transport-heavy deps
independently of the SDK workspace):

```bash
cd rust/connectors
cargo build && cargo test
```

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

## Stability & versioning

**Build a connector once, and it keeps working — you are never forced to
upgrade.** A connector is a binary you build and run; whether it stays accepted
depends only on the **wire contract**, which is frozen (`event.proto` +
`schema_version="v1"` + the seal envelope), pinned by
[`vendor/contract/`](vendor/contract/), and proven by the golden vectors. The SDK
API (`EventBuilder` / `seal` / …) is just a convenience for *building* those
bytes — if it ever changes, only a deliberate rebuild is affected, never a running
binary. **Pin the released tag `v0.1.0`, not a branch.**

The full guarantee — what we will and won't change within `contract-v1` — is in
[COMPATIBILITY.md](COMPATIBILITY.md). Security issues: [SECURITY.md](SECURITY.md).

## Contributing & license

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Every source file
carries an SPDX header. Commits require a [DCO](CONTRIBUTING.md) sign-off
(`git commit -s`). Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request; release
notes are in [CHANGELOG.md](CHANGELOG.md).
