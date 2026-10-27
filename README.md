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
| 9 | [Register with Core](#9-register-with-core) | everyone |
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
   rejects an entity type it does not recognise, and moves an attribute it does
   not govern out of the governed fields, or rejects the event on a strict
   site. Neither shows up at your end, so settle these before you write any
   mapping.
3. **A signing key.** Generate it yourself:

   ```bash
   scripts/gen-connector-key.sh acme-radar-1
   ```

   This writes `acme-radar-1.seed` (keep secret) and prints the public key.
4. **The NATS endpoint and credentials**, which come from whoever runs Core
   when you register in [section 9](#9-register-with-core). If that is you,
   one command on the Core host produces all four items as a packet.

You can build and test everything without items 1 and 4. You only need them to
send real events.

**To build from source** you need a current stable Rust toolchain from
[rustup.rs](https://rustup.rs) and, for containers, Docker. The release
tarball and the images need neither. Footprint, ports and timings:
[section 10](#footprint-ports-and-timings).

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
git clone --depth 1 --branch v0.6.5 https://github.com/promaka/ajar-connectors
```

**Step 2. Add it to your build.**

| Language | Command |
|---|---|
| Rust | `ajar-connector = "0.6.5"` |
| Python | `pip install ajar-connector==0.6.5` |
| Go | `go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.6.5` |
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

**Step 4. Build an event.** For one incoming `frame`, the bytes your source
gave you:

```python
from ajar_connector import EventBuilder

event = (EventBuilder("acme-radar-1", "mim:aircraft")   # source_id, entity type
         .new_id()                                       # fresh UUIDv7
         .now()                                          # RFC 3339 timestamp
         .location(25.27, 51.52, 10600.0)                # lat, lon, metres
         .attribute("speed", "231.50")                   # governed, m/s
         .metadata("icao", "4CA2D6")                     # ungoverned, native id
         .payload(frame)                                 # your bytes, verbatim
         .build())
```

Governed attributes are checked against the ontology. Metadata is not, and is
always kept. A native identifier goes in metadata, never in `id`; when its
standard is one the contract names, it also goes in the governed `alt_id` and
`alt_id_standard` pair (see [ATTRIBUTES.md](rust/connectors/ATTRIBUTES.md)).

**Step 4a. Work out what to map to.** The SDK does not do this for you. A
wrong entity type is rejected by Ajar. A wrong attribute name is taken out of
the governed fields on a default site, and rejects the event on a strict one.
Neither raises an error at your end.
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

**The same three steps in Rust:**

```rust
use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

let seed: [u8; 32] = std::fs::read("acme-radar-1.seed")?.try_into().expect("a 32-byte seed");
let key = SigningKey::from_bytes(&seed);

let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
    .new_id()
    .now()
    .location(25.27, 51.52, 10600.0)
    .attribute("speed", "231.50")
    .metadata("icao", "4CA2D6")
    .payload(frame)
    .build()?;

let sealed = seal(&canonical_bytes(&event), &key);
```

**And in Go:**

```go
import ajar "github.com/promaka/ajar-connectors/go/ajarconnector"

seed, _ := os.ReadFile("acme-radar-1.seed")
key, err := ajar.SigningKeyFromSeed(seed)

event, err := ajar.NewEventBuilder("acme-radar-1", "mim:aircraft").
    NewID().
    Now().
    Location(25.27, 51.52, 10600.0).
    Attribute("speed", "231.50").
    Metadata("icao", "4CA2D6").
    Payload(frame).
    Build()

canonical, err := ajar.CanonicalBytes(event)
sealed := ajar.Seal(canonical, key)
// publish with the headers from ajar.IngestHeaders(event)
```

Longer guides: [Python](docs/embedding-python.md) · [C++](docs/embedding-cpp.md).
The [Rust](rust/examples/connector-template/) and
[Go](go/examples/connector-template/) templates are complete programs built
from these calls.

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

No repo checkout needed: each connector's release on the
[releases page](https://github.com/promaka/ajar-connectors/releases) carries a
tarball for your platform, `ajar-<name>-<version>-<target>.tar.gz`, with the
binary, its example config, README and changelog; `ajar-doctor` is released the
same way. Verify it against the `.sha256` beside it, then start from the config
inside. Releases up to 0.6.5 shipped every connector in one
`ajar-connectors-<version>-<target>.tar.gz`.

**Step 3. Edit four values.**

```toml
source_id = "acme-radar-1"                        # from section 1
nats_url = "tls://ajar.example.mil:4222"          # from section 9
signing_key_path = "./acme-radar-1.seed"          # from section 1; /etc/ajar/… once deployed

[transport]                                        # how bytes reach the connector
kind = "udp-multicast"
bind = "0.0.0.0:8600"
group = "239.2.3.1"
```

Any connector runs on any transport. The full list is in
[section 10](#transport-is-orthogonal-to-protocol).

**Step 4. Run it once locally.** The seed file from section 1 must exist at
the path you gave; nothing else is needed yet.

```bash
cargo build --release --manifest-path rust/connectors/Cargo.toml -p ajar-asterix
./rust/connectors/target/release/ajar-asterix --profile ./asterix.toml   # config and key parse: prints your profile
./rust/connectors/target/release/ajar-asterix ./asterix.toml             # runs
```

What you will see: `connector starting`, then a `heartbeat` line every 15
seconds with `received`, `published` and `rejected` counts. Until section 9
gives you a real endpoint, the broker connection is retried quietly and
events are not kept, so the counts prove the decode, not the delivery.

To watch events arrive and verify before then, use the five-minute loop at
the top of this page. Its sink trusts only keys it knows, so register yours
first: in `deploy/dev/sink.toml`, add

```toml
[sources]
"acme-radar-1" = "<the public key hex that gen-connector-key.sh printed>"
```

then start the loop and set `nats_url = "nats://127.0.0.1:4222"` in your
connector's config. The sink logs each verified event and `audit` proves the
chain.

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

It validates the mapping against the ontology at start-up and refuses a name
it cannot place. Then the same `heartbeat` counts as section 4, step 4: the
decode is proven locally, the delivery once section 9 gives you an endpoint.

**Step 5.** Go to [section 7](#7-deploy-it).

Limits (flat fields only, one record per frame): [generic connector](rust/connectors/generic).

---

## 6. Set up: write a new connector

Two routes. Pick by where the connector will run.

| Route | Pick it when | What you get |
|---|---|---|
| **6a. A parser on the shared runtime** | it runs next to the equipment: a sidecar, a container, a binary on an edge box | every transport, mTLS, store-and-forward, health, the doctor, `--profile` and a container image, all by config; you write one parser |
| **6b. A standalone program** | you want to own the process, or write it in Python, Go or C++ | the SDK's three calls in a template you keep |

### 6a. A parser on the shared runtime

**Step 1. Scaffold it.**

```bash
scripts/new-connector.sh acme-legacy
```

This writes `rust/connectors/acme-legacy`, a crate named `ajar-acme-legacy`
that builds, runs and passes its tests before you touch it, and registers it
in the workspace.

**Step 2. Write the parser.** One file,
`rust/connectors/acme-legacy/src/acme_legacy.rs`: `decode()` turns one frame
into your record, `to_event()` maps the record onto an event. The tests pin
the rules every connector keeps: the raw frame sealed in `payload`, canonical
units, the feed's own identifier as `source_uid`, a typed error for bad input
and never a panic. [AGENTS.md](AGENTS.md) is the full specification, with a
worked example to copy for each kind of format.

**Step 3. Test and run it.** The example config names the seed
`./acme-legacy-1.seed`, so make one first, as in section 1.

```bash
scripts/gen-connector-key.sh acme-legacy-1
cargo test --manifest-path rust/connectors/Cargo.toml -p ajar-acme-legacy
cargo build --release --manifest-path rust/connectors/Cargo.toml -p ajar-acme-legacy
./rust/connectors/target/release/ajar-acme-legacy --profile ./rust/connectors/acme-legacy/acme-legacy.example.toml
./rust/connectors/target/release/ajar-acme-legacy ./rust/connectors/acme-legacy/acme-legacy.example.toml
```

The example config reads newline-delimited frames pushed over TCP; change
`[transport]` to whatever your equipment does, as in section 4, step 3.

**Step 4.** Go to [section 7](#7-deploy-it). For a container, section 7b
builds your crate by name. To have `ajar-up` start it from a packet, the
Core operator names it with `--protocol acme-legacy` when registering it,
as [section 9](#9-register-with-core) shows; the binary only has to sit
beside `ajar-up` or on `PATH`.

### 6b. A standalone program

**Step 1. Copy the template** for your language:
[Rust](rust/examples/connector-template/) · [Python](python/examples/connector_template.py) ·
[Go](go/examples/connector-template/) · [C++](cpp/examples/connector_template.cpp).

**Step 2. Edit the two blocks marked `EDIT`.** Describe your record, then map it
to an event. Around fifteen lines.

**Step 3. Run it against a sample** without any infrastructure:

```bash
cd rust/examples
echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' | cargo run -p connector-template -- --dry-run
```

**Step 4.** Go to [section 7](#7-deploy-it). The template reads stdin and
publishes with its own NATS client; transports, TLS and health are yours to
add, which is the trade for owning the process.

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
Environment=AJAR_HEALTH_ADDR=0.0.0.0:9090
Restart=always
```

With a `nats://` URL, set `AJAR_REQUIRE_TLS=1` to refuse cleartext anyway:
the connector then fails closed if the `AJAR_TLS_*` files are missing rather
than silently downgrading a defence link. (A `tls://` URL demands this by
itself.)

### 7b. As a container

**Build the image yourself**, from the repository root. One Dockerfile builds
any connector crate by name: multi-stage, distroless, non-root, for the host
architecture. Add `--platform linux/arm64` for an ARM edge box.

```bash
docker build -f deploy/docker/Dockerfile.build \
  --build-arg WSDIR=rust/connectors --build-arg PKG=ajar-asterix \
  -t ajar-connector-asterix:0.6.5 .
```

A connector you wrote in section 6a is the same command with its crate name,
`PKG=ajar-acme-legacy`.

**Run it** with your config and seed mounted read-only:

```bash
docker run \
  -v ./asterix.toml:/etc/ajar/connector.toml:ro \
  -v ./acme-radar-1.seed:/etc/ajar/seed:ro \
  ajar-connector-asterix:0.6.5 /etc/ajar/connector.toml
```

Set `signing_key_path = "/etc/ajar/seed"` in the mounted config. Prebuilt
images are also published, privately, at
`ghcr.io/promaka/ajar-connector-<name>:<version>`, where `<version>` is that
connector's own version (each connector is versioned on its own; its
`CHANGELOG.md` lists them, e.g. [asterix](rust/connectors/asterix/CHANGELOG.md)).
The packages page lists which connectors and versions exist, and your operator
can grant a pull secret with `read:packages`. From each connector's first
release after 0.6.5, its image names what it is and the wire contract it emits,
so you can check it against what your Core accepts before you deploy it:

```bash
docker inspect --format '{{ index .Config.Labels "ajar.connector.version" }} {{ index .Config.Labels "ajar.contract" }}' \
  ghcr.io/promaka/ajar-connector-asterix:<version>
# <version> v1
```

### 7c. On Kubernetes

```bash
kubectl create secret generic radar-seed --from-file=seed=acme-radar-1.seed

helm install radar deploy/helm/connector \
  --set connector.name=asterix \
  --set image.tag=0.6.5 \
  --set signingSeed.existingSecret=radar-seed \
  --set-file connector.config=./asterix.toml
```

`image.tag` is the asterix connector's own version, not the SDK's. The chart
renders your config into a ConfigMap, mounts the key from the Secret,
and can restrict egress to NATS only. Pull secrets, mTLS and health probes:
[chart README](deploy/helm/connector).

### 7d. Health and metrics

Set `AJAR_HEALTH_ADDR=0.0.0.0:9090` on any method. Gives `/healthz` and
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

### 7f. Mark what you publish

Core's clearance rules read a marking off each event: a classification, who
it is releasable to, whose policy the level belongs to, and handling caveats.
The wire formats themselves rarely carry one (STANAG 4676 does, and the
connector normalises it), so without this block every event from a stock
connector reaches Core unclassified. Four optional lines stamp every event
before it is sealed, so the marking is inside the signature and travels with
the provenance:

```toml
[marking]
classification = "restricted"   # unclassified | restricted | confidential | secret | top-secret
releasable_to = ["GBR", "ITA"]
policy = "NATO"
caveats = ["EXERCISE"]
```

Any one field is enough: a synthetic or training feed marks itself
`caveats = ["EXERCISE"]` and nothing else. The block is a floor, not a
ceiling: a marking the feed carries stays beside it, and Core takes the
higher level. A level outside the five refuses to start, because Core
would ignore the tag and the events would ship unclassified.
`ajar-doctor` prints the exact tags a config will stamp before any event
flows.

### 7g. When nothing flows

`ajar-doctor connector.toml` checks the setup step by step (config, signing
key, marking, registration, endpoint, TLS, clock) and says which onboarding step is
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

## 9. Register with Core

Ajar accepts events only from a registered identity. Registration is done by
whoever runs the Core you are connecting to. Nobody else is involved, and
nothing in this repository phones home.

**If you run Core yourself,** skip the exchange below. On the Core host, in
its material directory, one command registers the connector, mints its
credentials and writes a packet:

```bash
ajar onboard acme-radar-1 --mint --types mim: --protocol asterix \
  --nats tls://<core-host>:4222 --sign sovereign.key --policy policy.rego \
  --activate-policy --policy-version v<N> --material-dir . \
  --control-url http://127.0.0.1:9092 --idp-key idp.key --sub <operator>
```

It mints the signing key and the mTLS client certificate, registers the
public key with Core without a restart, writes and activates the policy
line, and produces `acme-radar-1.packet.tar`. Carry that file to the
connector host and run `./ajar-up acme-radar-1.packet.tar`, as in
[section 4](#4-set-up-run-a-prebuilt-connector).

`--protocol` names the connector `ajar-up` starts: it runs `ajar-<protocol>`
from beside itself or from `PATH`. A connector you built in
[section 6a](#6a-a-parser-on-the-shared-runtime) is therefore
`--protocol acme-legacy`, with no change on Core. A key you generated
yourself goes in as `--pubkey <64 hex characters>` instead of `--mint`, and
the packet then omits the signing key. A consumer is `ajar onboard <id>
--consumer`.

The command's own help lists every flag, and the Core bundle's runbook,
`deploy/site/RUNBOOK.md` section 4, has the connector commands; a fuller
connector onboarding guide joins the bundle's `docs/` from Core 0.1.28.

**If someone else runs Core,** one exchange, no account:

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
(`FrameParser`) plus a few lines of wiring: `scripts/new-connector.sh <name>`
writes both, and [AGENTS.md](AGENTS.md) is the specification the parser follows.

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
| [sapient](rust/connectors/sapient) | SAPIENT (BSI Flex 335) | counter-UAS detections, tracks, sensor status and alerts, from edge nodes or a fusion node | TCP server (edge nodes connect in) / TCP client / file |
| [tak-cot](rust/connectors/tak-cot) | TAK / Cursor-on-Target | ground/air situational-awareness tracks | UDP multicast / unicast |
| [generic](rust/connectors/generic) | any flat JSON / CSV | the long tail, by field mapping rather than code | any of the below |
| [tak-egress](rust/connectors/tak-egress) | TAK / CoT (**egress**) | governed COP tracks OUT to a TAK Server, or straight to ATAK's mesh with no server, verbatim | NATS → TLS 8089, or multicast 239.2.3.1:6969 |
| [generic-egress](rust/connectors/generic-egress) | any JSON consumer (**egress**) | governed events OUT by field mapping, markings unmappable-away | NATS → HTTP |
| [sapient-egress](rust/connectors/sapient-egress) | SAPIENT (BSI Flex 335) (**egress**) | governed events OUT as detection reports from a registered sensor node, to a counter-UAS fusion node | NATS → TCP |
| [sink](rust/connectors/sink) | — (**development sink**) | verifies, persists and audit-chains events; runs the whole path without Core | NATS → SQLite |
| [doctor](rust/connectors/doctor) | — (**diagnostics**) | names the broken onboarding step when nothing flows | read-only probes |
| [feed-synthetic](rust/connectors/feed-synthetic) | — (**conformance source**) | one fixture on seven real wire formats, for building against and commissioning before equipment arrives | multicast / TCP / UDP |

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
| `tcp-client` | TCP stream (dial out) | `framing = "line"`, `"length-delimited"` (2-byte big-endian prefix) or `"length-u32le"` (4-byte little-endian prefix, as SAPIENT frames), auto-reconnect |
| `tcp-server` | TCP listen | sources that push to a configured address; multiple pushers |
| `http-server` | HTTP(S) listen (webhooks) | sources that only POST to a URL; optional TLS and client certs; refuses with 503 when saturated so the sender retries |
| `file` | tail a file | follows appends, handles rotation; `framing` as for TCP, so a binary capture replays from the start |
| `dir` | watch a drop directory | batch file drops (SFTP exports); reads files once settled |
| `exec` | run a CLI tool | reads its stdout; wraps any vendor binary |
| `stdin` | pipe | `producer \| ajar-<connector>`; `framing` as for TCP |
| `pcap-replay` | recorded capture | replays a .pcap with original timing - evaluate on real recordings |
| `serial` | RS-232/422/485 | shipped in `ajar-ais-nmea`; other connectors build with the `serial` feature |
| `mqtt` | subscribe a topic | needs the `mqtt` feature (IoT buses) |
| `rest-poll` | HTTP GET on interval | needs the `rest-poll` feature (pull-only APIs) |
| `ws-client` | WebSocket, connect out | needs the `websocket` feature; hosted live feeds, subscription message and auth headers supported |
| `dds` | subscribe a DDS topic | shipped in every ingress connector; the bus inside naval combat systems and under ROS 2; a lean build is `--no-default-features` |

The `dds` kind joins the domain as one more reader on a topic the ship's or the
robot's own systems already publish; nothing on their side changes, and the
bytes are signed as they cross. Only the default partition is joined. Full
onboarding, including registering the connector with the sovereign's control
plane, is in [ONBOARDING.md](ONBOARDING.md).

Build and test them on their own (they resolve their transport-heavy deps
independently of the SDK workspace):

```bash
cd rust/connectors
cargo build && cargo test
```

## Footprint, ports and timings

What a connector needs and costs, measured on this release, so a deployment
can be sized without asking anyone. The resource numbers come from
`scripts/footprint.sh`, which builds one connector, pushes 300,000 records
through it to a bus and prints the same table for your machine; the image
size is the build in section 7b; the quickstart time is the figure the CI
job `quickstart stopwatch` publishes in its summary on every run of `main`.

**Size**

| Artefact | Size |
|---|---|
| One connector binary, release build | about 10 MB |
| One connector image, distroless, non-root | about 65 MB |
| Release tarball, one connector plus its example config | about 10 MB, Linux x86_64 and aarch64 |

**Resources** (one connector, a 300,000-frame feed signed and published to
a local bus)

| Measure | Value |
|---|---|
| Resident memory, idle and under load | about 10 MB |
| Throughput on one laptop core | about 50,000 events a second |
| Store-and-forward spool, when enabled | bounded by `[spool] max_bytes`, 256 MiB by default, on disk |
| Helm chart defaults | requests 50m CPU and 64 MiB; limits 250m CPU and 128 MiB |

A connector is one small process. Size it for the spool if links drop, not
for the parsing.

**Ports**

| Direction | Port | Purpose |
|---|---|---|
| In | the one your `[transport]` binds, for example UDP 8600 or TCP 9300 | the equipment's feed; none for `file`, `dir`, `exec`, `stdin`, `tcp-client`, `mqtt`, `rest-poll` or `ws-client`, which read or dial out; `dds` joins the domain's own discovery ports |
| In, optional | 9090 | `/healthz` and `/metrics`, only when `AJAR_HEALTH_ADDR` is set |
| Out | 443 on a cluster install, 4222 on the single-server and dev stacks | one mutually-authenticated TLS connection to the bus; nothing else, and no connection to anyone but your Core |

The Helm chart's network policy restricts egress to the bus and DNS. A
connector never listens for Core; the bus is the only path in either direction.

**Timings**

| Step | Measured |
|---|---|
| Quickstart, from nothing to the first verified event in the sink | 165 s on the last CI run of `main`; the budget CI enforces is 900 s |
| `scripts/new-connector.sh` to passing tests, clean clone | 20 s |
| First release build of one connector, clean clone | 50 s |
| First container build with `Dockerfile.build`, nothing cached | about 12 min; rebuilds reuse the cached stages |
| `--profile`, `ajar-doctor`, `ajar-up` from a packet | seconds |

Clean-clone figures assume the Rust toolchain and crate cache are present;
the first `cargo build` on a new machine also downloads dependencies.

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

Pin the released tag `v0.6.5`, not a branch.

Three things carry a version, and each moves on its own:

| What | Version | Released as | Where it is recorded |
|------|---------|-------------|----------------------|
| Wire contract | `v1` | nothing to install; frozen | [`vendor/contract/CONTRACT_VERSION`](vendor/contract/CONTRACT_VERSION) |
| SDK (Rust, Go, Python, C++) | one semver for all four | tag `vX.Y.Z`; crates.io, PyPI, Go module, C++ tarball | [`CHANGELOG.md`](CHANGELOG.md) |
| Each connector or tool | its own semver | tag `<name>-vX.Y.Z`; image `ajar-connector-<name>:X.Y.Z` and a tarball | `rust/connectors/<name>/CHANGELOG.md` |

Compatibility with Core is decided by the contract, not by matching versions: a
connector at any version that emits `v1` is accepted by a Core that accepts
`v1`. A connector's version tells you what changed in it. The entity types and
attributes it emits count as its public interface, so renaming or removing one
is a major version.

[COMPATIBILITY.md](COMPATIBILITY.md) states exactly what will and will not change
within `contract-v1`. Report security issues per [SECURITY.md](SECURITY.md).

## Contributing & license

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Every source file
carries an SPDX header. Commits require a [DCO](CONTRIBUTING.md) sign-off
(`git commit -s`). Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request; release
notes are in [CHANGELOG.md](CHANGELOG.md).
