<!-- SPDX-License-Identifier: Apache-2.0 -->
# Onboarding

How to get your data into Ajar, or Ajar's verified data into your system, in
the fewest steps that exist. Read the short version, then jump to the one
section that matches you.

## The short version

Two questions decide everything:

1. **Which direction?** Sending data in is *producing*. Receiving verified
   data out is *consuming*.
2. **Where does the work run?** Our program next to your system means you
   write no code. Our library inside your own code means you write one call.

Rule of thumb: if your equipment already speaks a protocol, run our program.
If your software creates or processes the data itself, use the library.

| | Our program next to your system | Our library inside your code |
|---|---|---|
| **Producing** | [Section 1](#1-you-were-given-an-invite): one command | [Section 3](#3-sending-from-your-own-code): one call per event |
| **Consuming** | [Section 1](#1-you-were-given-an-invite): one command | [Section 4](#4-receiving-in-your-own-code): one call per stream |

Whichever box you are in, the first thing you need is an invite.

## 1. You were given an invite

Your operator (whoever runs Ajar for you) ran one command on their side and
sent you a single file, `<your-id>.invite`. If you run Core yourself, you are
the operator: the command is `ajar invite <your-id> --connector <type>` on the
Core host, with `--consumer` for an egress connector. A connector whose types
are its own fragment rather than MIM's, such as SAPIENT, adds
`--entity-file <fragment>.json` with the file shipped beside its binary. The
invite contains everything you need, and nothing you have to create yourself:

| File | What it is |
|---|---|
| `manifest.json` | your connector ID, your role, the connector type, the broker address, the subject |
| `manifest.sig` | the operator's signature over the manifest. See [Keys](#keys) for what it proves |
| `egress.pub` | the public half of the operator's egress key, which verifies that signature |
| `signing.key` | your private signing key (producers only) |
| `mtls.crt`, `mtls.key` | your certificate and key for connecting to the broker |
| `ca.crt` | the operator's certificate authority, so you know you are talking to the real broker |

### Three steps

1. From [GitHub releases](https://github.com/promaka/ajar-connectors/releases),
   download `ajar-connectors` for your platform, unpack it and set it up once:
   ```bash
   tar xzf ajar-connectors-<version>-<platform>.tar.gz
   sudo ./ajar-connectors-*/ajar-connectors setup
   ```
2. Install the connector type your invite names:
   ```bash
   sudo ajar-connectors install adsb
   ```
3. Join:
   ```bash
   sudo ajar-connectors join <your-id>.invite
   ```

A setup with `sudo` is for all users and belongs to root, so every command runs
with `sudo`. A setup without it (`~/.ajar-connectors`) is yours, and needs none.

`join` checks the invite is intact, places your keys with locked-down
permissions, writes the config, runs the preflight, shows what it will do and
starts the connector. `ajar-connectors status` shows it running. See the
[`ajar-connectors` README](rust/connectors/cli/README.md) for every command.

**If you are a producer**, the connector for your data format starts and
begins reading your equipment's feed. Your equipment is not touched.

**If you are a consumer**, `join` asks where to deliver, or takes `--target`:
`tls://<tak-server>:8089` for a TAK server, the URL to post to for HTTP, or
the fusion node's `host:port` for SAPIENT. The egress connector's own settings
go in a file passed with `--settings`: the TLS files your TAK server enrolled
for this connector under `[tak]`, or the field mapping under `[mapping]` for
HTTP. Each egress connector's README lists them.

### Useful options

| Option | When |
|---|---|
| `--check` | check the invite, this machine and the connection, and change nothing. |
| `--no-start` | create the instance without starting it, for example when the broker is not reachable yet. Only failed network checks are let through. |
| `--settings <file>` | local settings for the connector, such as `marking`, `spool`, or an egress connector's own tables. |
| `--version <version>` | run another installed version than the newest. |
| `--yes` | skip the confirmation, for scripts. |

### If it does not start

When the preflight fails, `join` stops before creating anything and prints what
is wrong and how to fix it. When the connector then fails to start, the
instance stays, and `logs` and `start` take it from there. The three common
ones:

- **The invite is not intact**: the file changed after the operator made it.
  Ask the operator to send it again.
- **Broker unreachable**: your firewall must allow one outbound connection to
  the broker address in the invite. Nothing connects back to you.
- **No data on the local port**: your equipment broadcasts on a different port
  than the format's standard one. Ask the operator for an invite with the
  right transport.

When the invite held private keys, `join` offers to delete it once the instance
exists. Your keys are already placed.

## 2. You do not have an invite yet

Ask your operator for one. They need two things from you:

1. A name for your connector, such as `acme-radar-1`.
2. What you will send: the data format if your equipment speaks a standard
   (see [CONNECTORS.md](CONNECTORS.md)), or the entity types and attributes
   if you are writing code (see [docs/mapping-to-mim.md](docs/mapping-to-mim.md)).

If your policy says private keys must be made on your own machine, send a
request instead of waiting: see [Keys](#keys).

While you wait, everything can be built and tested with no invite and no
broker. The templates run with `--dry-run` and need no key; a shipped
connector proves its config and key with `--profile`, which opens no transport
and publishes nothing:

```bash
cd rust/examples && echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
  | cargo run -p connector-template -- --dry-run
ajar-generic --profile ./generic.toml     # needs only the seed file the config names
```

## 3. Sending from your own code

Your software creates the data, so it should sign it at the source. Install
the library for your language, pinned to the release:

```toml
# Rust, in Cargo.toml
ajar-connector = "0.6.6"
```
```bash
go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.6.6
pip install "ajar-connector[producer]==0.6.6"
```

For C++ see [docs/embedding-cpp.md](docs/embedding-cpp.md).

Then it is one connect and one call per event. Python:

```python
from ajar_connector.producer import connect, publish_assessment

producer = await connect(nats_url, source_id="acme-fuser-1", signing_seed="acme-fuser-1.seed")
event_id = await publish_assessment(
    producer,
    entity_type="mim:aircraft",
    model="fuser@1.0",                 # what produced it, name@version
    derived_from=[source_event_id],    # the governed events it reasoned over
    location=(25.27, 51.52, 10600.0),
)
```

Both `model` and `derived_from` are required: the boundary refuses a derived
event without lineage. The complete program is
[examples/derived_producer.py](python/examples/derived_producer.py).

Rust, Go and C++ are the same three steps everywhere: build the event, seal
it, publish it. The [README](README.md#3-set-up-inside-your-own-code) has
each language's snippet.

Two rules the library enforces so you cannot get them wrong:

- **Every event gets a fresh id.** Your own identifier (serial number, track
  id, MMSI) goes in metadata, where it is always kept.
- **If your event was derived from other events**, it must name the model and
  the events it came from. The boundary refuses a derived event without that.
  See the [Python guide](docs/embedding-python.md#publishing-derived-events-ai-assessments).

## 4. Receiving in your own code

One call per language. Your callback only ever sees events whose signature
verified under the operator's egress key. There is no way to receive an
unverified event through the library.

```python
from ajar_connector.consumer import consume      # pip install "ajar-connector[consumer]"

async for d in consume(url, subject="ajar.egress.>", egress_verifying_key=key,
                       skip_source_ids={"acme-fuser-1"}):
    handle(d.event)
```

Go uses `VerifyingHandler`, Rust `consumer::verified_events` (feature
`consumer`), C++ `ajar::verifying_handler`. All take the same two guards:
`skip_source_ids`, so you never consume your own output, and `skip_derived`,
to keep only sensor-original events. All count accepted, rejected and skipped
for your metrics. These calls handle one message at a time; the `verify` call
beneath them takes no lock, so you can verify distinct events in parallel.

## 5. Building a new connector

Only for a format that needs real parsing and is not in
[CONNECTORS.md](CONNECTORS.md). If your source emits flat JSON or CSV, you do
not need this: the [generic connector](rust/connectors/generic) maps it from a
config file.

1. Start from one of two places. For a connector that runs next to the
   equipment, scaffold it on the shared runtime and write one parser:
   `scripts/new-connector.sh <name>`, as
   [README section 6a](README.md#6a-a-parser-on-the-shared-runtime)
   walks through. To own the process, or to write it in another language,
   copy the template and edit the two spots marked `EDIT`, about fifteen
   lines: describe your record, then map it to an event.
   [Rust](rust/examples/connector-template/) ·
   [Python](python/examples/connector_template.py) ·
   [Go](go/examples/connector-template/) ·
   [C++](cpp/examples/connector_template.cpp)
2. Run it with `--dry-run` and look at the events it prints.
3. Run the conformance gate (below). Green means your bytes are exactly what
   Ajar accepts.
4. Send your operator the connector's profile. It contains your public key
   and the entity types you emit, nothing secret. A connector on the shared
   runtime prints its own:
   ```bash
   ajar-<connector> --profile ./config.toml
   ```
   A connector built from a template does not take `--profile`; build the
   same document with `ConnectorProfile` in the SDK, which
   [README section 9](README.md#9-register-with-core) names.

The transport is a config choice, not code: UDP, multicast, TCP either way,
HTTP, serial, MQTT, a file, a directory, a pipe, a polled REST endpoint, a
WebSocket, or a recorded pcap. The full list is in the
[README](README.md#transport-is-orthogonal-to-protocol).

## 6. Check it works

**Before anything is connected**, prove your build is byte-compatible:

```bash
(cd rust && cargo test -p conformance --test golden_vectors)      # Rust
(cd go && go test ./conformance/ -count=1)                         # Go
(cd python && PYTHONPATH=. python3 conformance/golden_vectors.py)  # Python
cmake -S cpp -B cpp/build && cmake --build cpp/build && ctest --test-dir cpp/build   # C++
```

Each line runs on its own from the repository root.

**When nothing flows**, run the check. It walks your setup in onboarding
order and names the first broken step in plain words. It never publishes an
event, so it is safe against a production broker:

```bash
ajar-connectors check --config connector.toml
```

From your own code there is no connector config, so write a small one with the
values your code runs with, and the `AJAR_TLS_*` variables set as usual:

```toml
source_id = "acme-radar-1"
nats_url = "tls://broker.example:4222"
signing_key_path = "connector.seed"

[transport]
kind = "stdin"
```

**Once running**, set `AJAR_HEALTH_ADDR=0.0.0.0:9090` for `GET /healthz` and
`GET /metrics` (published, skipped, publish errors). The Helm chart wires
these by default.

## Reference

### Keys

Three kinds of key material exist. All of them arrive in the invite, unless
you made a request.

1. **Your signing key.** An Ed25519 keypair. The private half signs every
   event you send; the operator registered the public half when they made
   your invite. Consumers do not have one.
2. **The operator's egress key.** Only its public half travels. It signed your
   invite, and it signs every event that passed governance, so consumers
   verify everything with this one key.
3. **Transport credentials.** A client certificate and key for the broker
   connection, plus the operator's CA certificate. These protect the pipe;
   the signing key protects the data.

`join` verifies `manifest.sig` with the `egress.pub` in the invite, then
checks each file the manifest lists against its sha256. That detects a change
made after the operator made the invite. Someone who also replaces
`egress.pub` can sign it again, so the first handover rests on the channel the
operator sends the invite over, the same as `ca.crt`.

If your policy says private keys must be made on your own machine, make them
there and send the operator only the public halves:

```bash
ajar-connectors request adsb acme-radar-1    # writes acme-radar-1.request
```

The operator answers with `ajar invite acme-radar-1.request`. That invite holds
no private keys, and `join` takes them from where `request` left them, on this
machine only.

The only key published in this repository is the golden-vector test seed,
which byte-exact conformance requires. Never sign production events with it.

### How data flows

```
your system ──▶ connector ──▶ broker ──▶ Ajar Core ──▶ broker ──▶ consumers
                 signs with            verifies your key,        verify with
                 your key              checks policy,            the egress key
                                       re-signs with egress key
```

Trust lives in the signature, not the pipe. An event can cross an untrusted
or relayed link and Core still knows it is authentic and unmodified. The
connector never needs to know where Core is, only where the broker is.

### Where things run

The connector runs at the edge, with the data source. Core runs where
governance and storage live. The broker sits wherever the two should meet:

- **Central**: edge connectors publish to one broker at the hub.
- **Disconnected outpost**: the outpost runs its own broker and Core and
  syncs to the hub when a link returns.
- **Edge gateway**: many sensors funnel through a small local broker that
  relays to the hub and buffers during outages.

The connector code is identical in all three. Add `spool = "/var/lib/ajar"`
to any connector's config and a broker outage loses nothing: events queue on
disk and replay, verified, when the link returns.

### Production behaviour

Built into every connector, nothing to add:

- A malformed record is logged and skipped. One bad record cannot take the
  connector down.
- A broker blip is logged and retried. The connection reconnects on its own.
- The broker authenticates connectors with a client certificate. `join`
  configures it from the invite. By hand, set `AJAR_TLS_CA`, `AJAR_TLS_CERT`
  and `AJAR_TLS_KEY` and use a `tls://` broker address.

### Installing without a network

On a connected machine, download `ajar-<type>-<version>-<platform>.tar.gz` and
its `.sha256` from the releases page. Copy both into `packages/` in the
ajar-connectors folder on the air-gapped machine; `ajar-connectors install
<type>` then installs from there, checked against the `.sha256`.

### Building for an air-gapped network

The install commands above fetch from the internet. On a connected machine,
at the release tag you intend to ship:

```bash
git clone --depth 1 --branch v0.6.6 https://github.com/promaka/ajar-connectors
cd ajar-connectors
mkdir -p .cargo && cargo vendor --manifest-path rust/Cargo.toml \
  -s rust/connectors/Cargo.toml -s rust/examples/Cargo.toml \
  vendor-crates/ > .cargo/config.toml                                  # Rust, all three workspaces
(cd go && go mod vendor)                                               # Go
pip download ./python -d wheels/                                       # Python
find . -type f -not -path './.git/*' -print0 | xargs -0 sha256sum -b > MANIFEST.sha256
```

The Rust line also writes the `.cargo/config.toml` that points every build
at the vendored crates; about 600 MB in all. Carry the directory across,
verify `MANIFEST.sha256` on arrival, and build offline with
`cargo build --offline --manifest-path rust/connectors/Cargo.toml`,
`go build -mod=vendor` or `pip install --no-index --find-links wheels/`.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Rejected: signature invalid | public key not registered, wrong seed, or a `source_id` that differs from the registered one | compare the registered public key with yours; check `AJAR_SOURCE_ID` |
| An attribute never reaches policy or the picture; a strict site rejects the event | an attribute the entity type does not declare: a default site keeps it only as metadata, a strict site rejects the event | use a declared name, or ask the operator to add it |
| Rejected: unknown entity type | the type is not in Core's ontology | use a declared type, or get yours registered |
| Build error: unnamespaced entity type | the type is not `mim:<type>` or `x:<vendor>:<type>` | namespace it |
| Nothing arrives, no error | wrong subject or `source_id` | the subject is `ajar.ingest.<source_id>` with your assigned id |

Anything that needs a new entity type or attribute lives on the Core side.
Talk to your operator; that is the one part not in this repository.
