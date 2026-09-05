<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connectors

[![ci](https://github.com/promaka/ajar-connectors/actions/workflows/ci.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/ci.yml)
[![image](https://github.com/promaka/ajar-connectors/actions/workflows/image.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/image.yml)
[![deploy](https://github.com/promaka/ajar-connectors/actions/workflows/helm.yml/badge.svg)](https://github.com/promaka/ajar-connectors/actions/workflows/helm.yml)
[![conformant: contract-v1](https://img.shields.io/badge/conformant-contract--v1-2ea44f)](docs/wire-contract-v1.md)

Apache-2.0 SDK for sending signed events to Ajar, a defence data integration and
governance plane. Standalone: it does not depend on the private Ajar core.

```
your data ──▶ build Event ──▶ canonical bytes ──▶ seal (Ed25519) ──▶ ajar.ingest.<source_id>
```

## Contents

| # | Section | Read it if |
|---|---------|-----------|
| 1 | [What you need before you start](#1-what-you-need-before-you-start) | everyone |
| 2 | [Choose how to connect](#2-choose-how-to-connect) | everyone |
| 3 | [Set up: inside your own code](#3-set-up-inside-your-own-code) | you picked option A |
| 4 | [Set up: run a prebuilt connector](#4-set-up-run-a-prebuilt-connector) | you picked option B |
| 5 | [Set up: map flat JSON or CSV](#5-set-up-map-flat-json-or-csv) | you picked option C |
| 6 | [Set up: write a new connector](#6-set-up-write-a-new-connector) | you picked option D |
| 7 | [Deploy it](#7-deploy-it) | options B, C, D |
| 8 | [Prove your bytes are correct](#8-prove-your-bytes-are-correct) | everyone |
| 9 | [Register with the operator](#9-register-with-the-operator) | everyone |
| 10 | [Reference](#language-support) | as needed |

Read 1 and 2, then jump to your one setup section, then 7 to 9.

## See it work in five minutes

No hardware, no registration, no Ajar Core. One command starts a bus, a signed
publisher and a verifying sink that records every event into a hash-chained
store:

```bash
docker compose -f deploy/dev/compose.yml up --build
```

Prove the record, and try to fake it:

```bash
docker compose -f deploy/dev/compose.yml run --rm sink audit /etc/ajar/sink.toml
# audit: INTACT — every signature and every link verified from stored bytes alone
```

To see the picture, the sink renders each verified event as Cursor-on-Target on
ATAK's mesh SA multicast group: open ATAK or WinTAK on the same network and the
tracks appear, no server and no setup. From a container that needs host
networking (Linux: add `-f deploy/dev/compose.map.yml`); without Docker, the
same loop runs as three bare binaries — see [deploy/dev](deploy/dev).

Every marker on that map is an event sealed at source, verified against a
registered key, and chained into an auditable record. Delete a row from the
database and `audit` names the exact record that is missing.

---

## 1. What you need before you start

1. **A `source_id`.** Your connector's identity, agreed with your Ajar operator.
   Example: `acme-radar-1`.
2. **An entity type and attribute names**, agreed with the same operator. Ajar
   discards an entity type or attribute name it does not recognise, without
   raising an error, so settle these before you write any mapping.
3. **A signing key.** Generate it yourself:

   ```bash
   scripts/gen-connector-key.sh acme-radar-1
   ```

   This writes `acme-radar-1.seed` (keep secret) and prints the public key.
4. **The NATS endpoint and credentials**, which the operator sends you after you
   register in [section 9](#9-register-with-the-operator).

You can build and test everything without items 1 and 4. You only need them to
send real events.

---

## 2. Choose how to connect

| Option | Your situation | Go to |
|---|---|---|
| **A** | You have a service and want it to send events from inside your own code | [section 3](#3-set-up-inside-your-own-code) |
| **B** | Your equipment already speaks ADS-B, AIS, CoT, MAVLink, ASTERIX or STANAG | [section 4](#4-set-up-run-a-prebuilt-connector) |
| **C** | Your source emits flat JSON or CSV | [section 5](#5-set-up-map-flat-json-or-csv) |
| **D** | Your format needs real parsing and none of the above covers it | [section 6](#6-set-up-write-a-new-connector) |

Options B, C and D run as a separate binary. Option A runs inside your process.

---

## 3. Set up: inside your own code

Your process, your deployment. The SDK builds, seals and verifies. You publish.

**Step 1. Get the SDK.** Rust, Python and Go install straight from their
package registries in step 2. C++ builds from source:

```bash
git clone --depth 1 --branch v0.5.11 https://github.com/promaka/ajar-connectors
```

**Step 2. Add it to your build.**

| Language | Command |
|---|---|
| Rust | `ajar-connector = "0.5.11"` |
| Python | `pip install ajar-connector==0.5.11` |
| Go | `go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.5.11` |
| C++ | `cmake -S cpp -B build && cmake --build build && cmake --install build --prefix /opt/ajar` |

C++ then links with:

```cmake
find_package(ajar_connector REQUIRED)
target_link_libraries(your_service PRIVATE ajar_connector::ajar_connector)
```

**Step 3. Load your signing key.**

```python
from ajar_connector import SigningKey
key = SigningKey.from_seed(open("acme-radar-1.seed", "rb").read())
```

**Step 4. Build an event.**

```python
from ajar_connector import EventBuilder

event = (EventBuilder("acme-radar-1", "mim:aircraft")   # source_id, entity type
         .new_id()                                       # fresh UUIDv7
         .now()                                          # RFC 3339 timestamp
         .location(25.27, 51.52, 10600.0)                # lat, lon, metres
         .attribute("speed", "231.50")                   # governed, m/s
         .metadata("icao", "4CA2D6")                     # ungoverned, native id
         .payload(raw_frame)                             # your bytes, verbatim
         .build())
```

Governed attributes are checked against the ontology. Metadata is not, and is
always kept. Put native identifiers in metadata, never in `id`.

**Step 4a. Work out what to map to.** The SDK does not do this for you, and a
wrong entity type or attribute name is discarded by Ajar without an error.
[docs/mapping-to-mim.md](docs/mapping-to-mim.md) lists the entity types, the
governed attribute names, the units, and the controlled vocabularies.

**Step 5. Seal it.**

```python
from ajar_connector import canonical_bytes, seal
sealed = seal(canonical_bytes(event), key)
```

**Step 6. Publish it** to `ajar.ingest.<source_id>` with your own NATS client,
with the message header `Nats-Msg-Id` set to the event's `id`. The broker uses
that header to drop duplicate deliveries (retries, reconnect races) inside its
duplicate window; without it, a retransmission becomes a second stored event.
The prebuilt connectors set it automatically.

**Step 7.** Go to [section 8](#8-prove-your-bytes-are-correct).

Longer guides: [Python](docs/embedding-python.md) · [C++](docs/embedding-cpp.md).
Rust and Go use the same three calls.

**Consuming governed events?** Verification is one call and structurally
unskippable in every SDK: Python `ajar_connector.consumer.consume`, Go
`ajarconnector.VerifyingHandler`, Rust `ajar_connector::consumer` (behind
`features = ["consumer"]`). Only signature-verified events ever reach your
code; tampered ones are counted and dropped inside the loop.

**Publishing AI or analytics output back in?** A derived event names what it
was derived from, and the boundary refuses one that does not. The drop-in
producer (`pip install "ajar-connector[producer]"`) makes lineage a required
argument; the one call you add is shown in
[examples/derived_producer.py](python/examples/derived_producer.py) and the
[Python guide](docs/embedding-python.md#publishing-derived-events-ai-assessments).

---

## 4. Set up: run a prebuilt connector

**The one-command path**: if your operator handed you a packet
(`<your-id>.packet.tar`), everything below collapses into:

```bash
./ajar-up your-id.packet.tar
```

It verifies the packet's signature and checksums, places your credentials,
writes the config, runs the doctor preflight, and starts the right connector
(producer packets) or a verified tap on governed egress (consumer packets:
add `--to-tak host:8089` or `--to-http <url>` for a real delivery target).
The manual steps below remain for operators who prefer them.

**Step 1. Pick your connector** from the [table in section 10](#reference-connectors).

**Step 2. Copy its example config.** Every connector ships one:

```bash
cp rust/connectors/asterix/asterix.example.toml ./asterix.toml
```

No repo checkout needed: the release tarball for your platform
(`ajar-connectors-<version>-<target>.tar.gz` on the
[releases page](https://github.com/promaka/ajar-connectors/releases)) carries
every connector binary, `ajar-doctor`, and these example configs; verify it
against the `.sha256` beside it, then start from the config inside.

**Step 3. Edit four values.**

```toml
source_id = "acme-radar-1"                        # from section 1
nats_url = "tls://ajar.example.mil:4222"          # from section 9
signing_key_path = "/etc/ajar/acme-radar-1.seed"  # from section 1

[transport]                                        # how bytes reach the connector
kind = "udp-multicast"
bind = "0.0.0.0:8600"
group = "239.2.3.1"
```

Any connector runs on any transport. The full list is in
[section 10](#transport-is-orthogonal-to-protocol).

**Step 4. Run it once locally** to check the config parses:

```bash
cargo build --release --manifest-path rust/connectors/Cargo.toml -p ajar-asterix
./rust/connectors/target/release/ajar-asterix ./asterix.toml
```

**Step 5.** Go to [section 7](#7-deploy-it).

---

## 5. Set up: map flat JSON or CSV

No code. You write field names.

**Step 1. Copy the example config.**

```bash
cp rust/connectors/generic/generic.example.toml ./generic.toml
```

**Step 2. Fill in the same four values as section 4** (source_id, nats_url,
signing_key_path, transport).

**Step 3. Write the mapping.** Ajar's name on the left, yours on the right.

```toml
[mapping]
format = "json"                   # or "csv"
entity_type = "x:acme:sensor"     # agreed in section 1
timestamp_field = "observed_at"
lat_field = "latitude"
lon_field = "longitude"
[mapping.attributes]              # governed, checked against the ontology
speed = "speed"
[mapping.metadata]                # ungoverned, native identifiers
sensor_id = "sensor_id"
```

**Step 4. Run it.**

```bash
cargo build --release --manifest-path rust/connectors/Cargo.toml -p ajar-generic
./rust/connectors/target/release/ajar-generic ./generic.toml
```

**Step 5.** Go to [section 7](#7-deploy-it).

Limits (flat fields only, one record per frame): [generic connector](rust/connectors/generic).

---

## 6. Set up: write a new connector

**Step 1. Copy the template** for your language:
[Rust](rust/examples/connector-template/) · [Python](python/examples/connector_template.py) ·
[Go](go/examples/connector-template/) · [C++](cpp/examples/connector_template.cpp).

**Step 2. Edit the two blocks marked `EDIT`.** Describe your record, then map it
to an event. Around fifteen lines.

**Step 3. Run it against a sample** without any infrastructure:

```bash
cd rust/examples
echo '{"lat":26.4,"lon":50.9,"alt_m":11000}' | cargo run -p connector-template -- --dry-run
```

**Step 4.** Go to [section 7](#7-deploy-it).

---

## 7. Deploy it

For options B, C and D. Pick one method. All three run the same binary with the
same config file.

### 7a. As a binary

```bash
./ajar-asterix /etc/ajar/asterix.toml
```

With systemd:

```ini
[Service]
ExecStart=/usr/local/bin/ajar-asterix /etc/ajar/asterix.toml
Environment=AJAR_TLS_CA=/etc/ajar/ca.pem
Environment=AJAR_TLS_CERT=/etc/ajar/connector.crt
Environment=AJAR_TLS_KEY=/etc/ajar/connector.key
Environment=AJAR_HEALTH_ADDR=0.0.0.0:9110
Restart=always
```

With a `nats://` URL, set `AJAR_REQUIRE_TLS=1` to refuse cleartext anyway:
the connector then fails closed if the `AJAR_TLS_*` files are missing rather
than silently downgrading a defence link. (A `tls://` URL demands this by
itself.)

### 7b. As a container

Images are private. Create a pull secret with `read:packages` for
`ghcr.io/promaka` first.

```bash
docker run \
  -v ./asterix.toml:/etc/ajar/connector.toml:ro \
  -v ./acme-radar-1.seed:/etc/ajar/seed:ro \
  ghcr.io/promaka/ajar-connector-asterix:0.5.11 /etc/ajar/connector.toml
```

### 7c. On Kubernetes

```bash
kubectl create secret generic radar-seed --from-file=seed=acme-radar-1.seed

helm install radar deploy/helm/connector \
  --set connector.name=asterix \
  --set image.tag=0.5.11 \
  --set signingSeed.existingSecret=radar-seed \
  --set-file connector.config=./asterix.toml
```

The chart renders your config into a ConfigMap, mounts the key from the Secret,
and can restrict egress to NATS only. Pull secrets, mTLS and health probes:
[chart README](deploy/helm/connector).

### 7d. Health and metrics

Set `AJAR_HEALTH_ADDR=0.0.0.0:9110` on any method. Gives `/healthz` and
`/metrics` with counters for received, published, rejected and
backpressure-dropped events, the spool (`connector_spooled_total`,
`connector_drained_total`, `connector_spool_failed_total`,
`connector_spool_corrupt_total`, `connector_spool_dropped_segments_total`)
and any connector-specific counters (e.g. `asterix_test_targets_total`,
`ttm_non_tracking_total`).

### 7e. Intermittent links (store-and-forward)

If the link drops, events queue on disk and replay in order when it comes
back. They were signed before publish, so nothing loses its provenance. One
line enables it:

```toml
spool = "/var/lib/ajar/spool"
```

That is the whole setup: 256 MiB bound, paced replay, oldest dropped (and
counted) if the bound fills. For a two-box deployment, give `nats_url` both
endpoints and the connector fails over by itself
(`nats_url = "tls://box-a:4443,tls://box-b:4443"`): one box down means
failover, both down means the spool. The full table tunes it:

```toml
[spool]
dir = "/var/lib/ajar/spool"   # a real disk, not tmpfs
max_bytes = 268435456          # bound; oldest segment dropped beyond it, counted
drain_rate = 50.0              # events/sec on replay: 70-80% of your registered rate
```

In a container, mount the directory as a volume (a PVC on Kubernetes): events
spooled to the container filesystem survive the link outage but not a
restart. `ajar-doctor` checks the directory is writable and reports any
backlog waiting to drain.

Without a spool configured the behavior is unchanged: a stalled publish sheds the event
and counts it. Spool activity appears on `/metrics`: spooled, drained,
failed appends, and segments dropped at the bound (the bound is enforced
per segment, so reconcile loss against
`connector_spool_dropped_segments_total`, not an event count).

### 7f. When nothing flows

`ajar-doctor connector.toml` checks the setup step by step (config, signing
key, registration, endpoint, TLS, clock) and says which onboarding step is
broken and what to do, reading the same config and `AJAR_TLS_*` environment
the connector uses. With no config file it reads `NATS_URL`, `AJAR_SOURCE_ID`
and `AJAR_SIGNING_SEED` instead, so a connector embedded in your own code
(option A) is diagnosed with zero files. Read-only on the wire, so it is safe
against a production endpoint. Ships in the release binaries next to the
connectors.

---

## 8. Prove your bytes are correct

Runs offline. No credentials, no Ajar Core, no contact with us.

**Step 1. Build the harness.**

```bash
cargo build --release --manifest-path rust/Cargo.toml -p conformance --bin ajar-conformance
```

**Step 2. Write an adapter** that reads a fixture on stdin and writes raw bytes
on stdout. Three lines. Copy
[the Python one](python/examples/conformance_adapter.py) or
[the Rust one](rust/examples/conformance-adapter/).

**Step 3. Run it.**

```console
$ ajar-conformance run --impl python3 your_adapter.py
ok   aircraft_with_attrs/canonical
ok   aircraft_with_attrs/sealed
...
Conformant — contract-v1 (14 vectors)
```

Exit 0 means your bytes match. Exit 1 names the vector that diverged.

**Step 4. Add it to your CI.**

```yaml
- run: ajar-conformance run --impl ./your-connector --report conformance.json
```

**Step 5.** Display the badge once green:

```markdown
[![conformant: contract-v1](https://img.shields.io/badge/conformant-contract--v1-2ea44f)](https://github.com/promaka/ajar-connectors/blob/main/docs/wire-contract-v1.md)
```

---

## 9. Register with the operator

Ajar accepts events only from a registered identity. One exchange, no account.

**Step 1. Produce your profile.** Any connector here derives it from your config:

```bash
ajar-asterix --profile ./asterix.toml
```

```json
{ "contract": "v1",
  "source_id": "acme-radar-1",
  "allowed_entity_types": ["mim:"],
  "max_payload_bytes": 65536,
  "verifying_key_hex": "e28a89…" }
```

Writing your own connector instead? Build the same document with
`ConnectorProfile` in your language.

**Step 2. Send it to your operator.** It contains your public key only. Your
private seed and your source code stay with you.

**Step 3. Receive** confirmation that your key and entity types are registered,
plus the NATS endpoint and credentials.

**Step 4. Put the endpoint in your config** (`nats_url`) and run.

---

## Language support

| Language | SDK | Conformance |
|----------|-----|-------------|
| Rust | `rust/ajar-connector` | reproduces all golden vectors |
| Go | `go/ajarconnector` | reproduces all golden vectors |
| C++ (desktop) | `cpp/` (protoc-C++) | reproduces all golden vectors |
| C++ (embedded) | `cpp/embedded/` (nanopb, no-heap) | reproduces all golden vectors |
| Python | `python/ajar_connector` | reproduces all golden vectors |

All five assert against the same [vectors.json](vendor/contract/vectors.json) and
produce byte-identical canonical bytes for every fixture. **Five independent
protobuf encoders** (prost, Go, libprotobuf, nanopb, Python) agreeing on every
hash is the proof, because protobuf serialization is not canonical by
specification. The C++ builds vendor their crypto (Monocypher Ed25519, no system
dependency); the embedded nanopb build links no protobuf runtime and allocates
nothing on the heap on the encode path.

## Reference connectors

`rust/connectors/` holds production connectors, one per open wire standard rather
than one per system. Any equipment already speaking that standard connects by
config alone.

They share a runtime crate, [`connectors/common`](rust/connectors/common), which
provides config, key loading, mTLS NATS, the transport layer, the seal-and-publish
loop, health and graceful shutdown. A new connector is therefore a format parser
(`FrameParser`) plus a few lines of wiring.

| Connector | Standard | What it feeds | Typical transport |
|-----------|----------|---------------|-------------------|
| [asterix](rust/connectors/asterix) | ASTERIX CAT021 / 048 / 062 | radar + ADS-B + fused air tracks | UDP multicast |
| [adsb](rust/connectors/adsb) | ADS-B (SBS-1 / BaseStation) | cooperative aircraft tracks | TCP client |
| [ais-nmea](rust/connectors/ais-nmea) | AIS + ARPA (TTM) over NMEA 0183 | maritime vessel + radar tracks | serial / TCP client / UDP |
| [gmti](rust/connectors/gmti) | STANAG 4607 (NATO GMTI) | ground moving-target detections | file / TCP / UDP |
| [klv](rust/connectors/klv) | STANAG 4609 / MISB ST 0601 (KLV) | FMV platform / sensor metadata | UDP / file |
| [stanag4676](rust/connectors/stanag4676) | STANAG 4676 (NATO ISR Tracking) | fused ISR tracks | TCP / file |
| [mavlink](rust/connectors/mavlink) | MAVLink v1/v2 | small-UAS / drone telemetry | UDP |
| [stanag4586](rust/connectors/stanag4586) | STANAG 4586 (NATO UAS Control) | military UAS telemetry | UDP |
| [tak-cot](rust/connectors/tak-cot) | TAK / Cursor-on-Target | ground/air situational-awareness tracks | UDP multicast / unicast |
| [generic](rust/connectors/generic) | any flat JSON / CSV | the long tail, by field mapping rather than code | any of the below |
| [tak-egress](rust/connectors/tak-egress) | TAK / CoT (**egress**) | governed COP tracks OUT to a TAK Server, verbatim | NATS → TLS 8089 |
| [generic-egress](rust/connectors/generic-egress) | any JSON consumer (**egress**) | governed events OUT by field mapping, markings unmappable-away | NATS → HTTP |
| [sink](rust/connectors/sink) | — (**development sink**) | verifies, persists and audit-chains events; runs the whole path without Core | NATS → SQLite |
| [doctor](rust/connectors/doctor) | — (**diagnostics**) | names the broken onboarding step when nothing flows | read-only probes |

Each maps a standard's position reports, and where present its identity and
tactical fields, onto Ajar tracks. Each connector's README states which message
types it covers.

[CONNECTORS.md](CONNECTORS.md) catalogues what each connector is for and the real
systems that speak each format: radars, AIS transponders, autopilots, UAS ground
stations and TAK devices.

### Transport is orthogonal to protocol

Parsing and delivery are separate concerns. No connector hard-codes how bytes
arrive, so any connector runs on any transport by config:

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
| `pcap-replay` | recorded capture | replays a .pcap with original timing - evaluate on real recordings |
| `serial` | RS-232/422/485 | shipped in `ajar-ais-nmea`; other connectors build with the `serial` feature |
| `mqtt` | subscribe a topic | needs the `mqtt` feature (IoT buses) |
| `rest-poll` | HTTP GET on interval | needs the `rest-poll` feature (pull-only APIs) |
| `ws-client` | WebSocket, connect out | needs the `websocket` feature; hosted live feeds, subscription message and auth headers supported |

DDS is reached through an external gateway that re-publishes onto one of these
(usually `udp-multicast` or `mqtt`), not as a native kind. Full onboarding,
including registering the connector with the sovereign's control plane, is in
[ONBOARDING.md](ONBOARDING.md).

Build and test them on their own (they resolve their transport-heavy deps
independently of the SDK workspace):

```bash
cd rust/connectors
cargo build && cargo test
```

## Not in scope

The SDK does not implement policy, audit, ontology enforcement, correlation or
the pipeline. Those belong to Ajar Core. The SDK produces valid signed events,
declares profiles and translates in and out. It never sees any secret beyond the
connector's own signing key.

## Stability & versioning

Build a connector once and it keeps working. You are never forced to upgrade.

Whether a connector stays accepted depends only on the wire contract:
`event.proto`, `schema_version="v1"` and the seal envelope. That contract is
frozen, pinned by [`vendor/contract/`](vendor/contract/) and proven by the golden
vectors.

The SDK API (`EventBuilder`, `seal` and the rest) is a convenience for building
those bytes. If it changes, only a deliberate rebuild is affected, never a
running binary.

Pin the released tag `v0.5.11`, not a branch.

[COMPATIBILITY.md](COMPATIBILITY.md) states exactly what will and will not change
within `contract-v1`. Report security issues per [SECURITY.md](SECURITY.md).

## Contributing & license

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Every source file
carries an SPDX header. Commits require a [DCO](CONTRIBUTING.md) sign-off
(`git commit -s`). Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request; release
notes are in [CHANGELOG.md](CHANGELOG.md).
