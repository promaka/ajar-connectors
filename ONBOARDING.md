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
| **Producing** | [Section 1](#1-you-were-given-a-packet): one command | [Section 3](#3-sending-from-your-own-code): one call per event |
| **Consuming** | [Section 1](#1-you-were-given-a-packet): one command | [Section 4](#4-receiving-in-your-own-code): one call per stream |

Whichever box you are in, the first thing you need is a packet.

## 1. You were given a packet

Your operator (whoever runs Ajar for you) ran one command on their side and
sent you a single file, `<your-id>.packet.tar`. It contains everything you
need, and nothing you have to create yourself:

| File | What it is |
|---|---|
| `manifest.json` | your name, your role, the broker address, the data format, the subject |
| `manifest.sig` | the operator's signature over the manifest, so tampering is detected |
| `<your-id>.signing.key` | your private signing key (producers only) |
| `<your-id>.mtls.crt`, `<your-id>.mtls.key` | your certificate and key for connecting to the broker |
| `ca.crt` | the operator's certificate authority, so you know you are talking to the real broker |

### Three steps

1. Download the release for your platform from
   [GitHub releases](https://github.com/promaka/ajar-connectors/releases) and
   unpack it. Every connector program is inside, including `ajar-up`.
2. Run one command:
   ```bash
   ./ajar-up <your-id>.packet.tar
   ```
3. That is it. `ajar-up` checks the packet's signature and file checksums,
   places your keys with locked-down permissions, writes the config, runs the
   health checks, and starts.

**If you are a producer**, the connector for your data format starts and
begins reading your equipment's feed. Your equipment is not touched.

**If you are a consumer**, verified events start streaming to your terminal.
To deliver them somewhere useful instead:

```bash
./ajar-up <your-id>.packet.tar --to-tak host:8089   # into a TAK server
./ajar-up <your-id>.packet.tar --to-http <url>      # into any web endpoint
```

### Useful options

| Option | When |
|---|---|
| `--no-exec` | do everything except start. Use this if you are embedding the library (sections 3 and 4): your keys are placed and checked, then your own code takes over. |
| `--check` | verify the packet and exit. Good for CI. |
| `--signing-key <file>` | you generated your own key and only gave the operator the public half. See [Keys](#keys). |
| `--dir <dir>` | where to unpack. Default is next to the packet. |

### If it does not start

`ajar-up` stops before starting anything and prints what is wrong and how to
fix it. The three common ones:

- **"does not verify under the packet's egress key"**: the file was altered
  or corrupted in transit. Ask the operator to resend it.
- **Broker unreachable**: your firewall must allow one outbound connection to
  the broker address in the manifest. Nothing connects back to you.
- **No data on the local port**: your equipment broadcasts on a different
  port than the format's standard one. Edit that one line in the generated
  config.

Delete the packet file once you are running. Your keys are already placed.

## 2. You do not have a packet yet

Ask your operator for one. They need three things from you:

1. A name for your connector, such as `acme-radar-1`.
2. What you will send: the data format if your equipment speaks a standard
   (see [CONNECTORS.md](CONNECTORS.md)), or the entity types and attributes
   if you are writing code (see [docs/mapping-to-mim.md](docs/mapping-to-mim.md)).
3. If you insist on generating your own signing key, its public half. See
   [Keys](#keys). Most people skip this and let the operator generate it.

While you wait, everything can be built and tested with no packet, no broker
and no key. Every connector has a dry run:

```bash
cd rust/examples && echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
  | cargo run -p connector-template -- --dry-run
```

## 3. Sending from your own code

Your software creates the data, so it should sign it at the source. Install
the library for your language, pinned to the release:

```toml
# Rust, in Cargo.toml
ajar-connector = "0.5.10"
```
```bash
go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.5.10
pip install "ajar-connector[producer]==0.5.10"
```

For C++ see [docs/embedding-cpp.md](docs/embedding-cpp.md).

Then it is one connect and one call per event. Python:

```python
from ajar_connector.producer import connect

conn = connect(nats_url, source_id="acme-fuser-1", signing_seed=seed)
conn.publish_assessment(entity_type="mim:aircraft", ...)
```

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
for your metrics.

## 5. Building a new connector

Only for a format that needs real parsing and is not in
[CONNECTORS.md](CONNECTORS.md). If your source emits flat JSON or CSV, you do
not need this: the [generic connector](rust/connectors/generic) maps it from a
config file.

1. Copy the template for your language and edit the two spots marked `EDIT`,
   about fifteen lines: describe your record, then map it to an event.
   [Rust](rust/examples/connector-template/) ·
   [Python](python/examples/connector_template.py) ·
   [Go](go/examples/connector-template/) ·
   [C++](cpp/examples/connector_template.cpp)
2. Run it with `--dry-run` and look at the events it prints.
3. Run the conformance gate (below). Green means your bytes are exactly what
   Ajar accepts.
4. Send your operator the connector's profile. A connector prints its own:
   ```bash
   ajar-<connector> --profile ./config.toml
   ```
   It contains your public key and the entity types you emit. Nothing secret.

The transport is a config choice, not code: UDP, multicast, TCP either way,
HTTP, serial, MQTT, a file, a directory, a pipe, a polled REST endpoint, a
WebSocket, or a recorded pcap. The full list is in the
[README](README.md#transport-is-orthogonal-to-protocol).

## 6. Check it works

**Before anything is connected**, prove your build is byte-compatible:

```bash
cd rust && cargo test -p conformance --test golden_vectors   # Rust
cd go && go test ./conformance/ -count=1                      # Go
cd python && PYTHONPATH=. python conformance/golden_vectors.py # Python
ctest --test-dir cpp/build                                     # C++
```

**When nothing flows**, run the doctor. It checks your setup in onboarding
order and names the first broken step in plain words. It never publishes an
event, so it is safe against a production broker:

```bash
ajar-doctor connector.toml
ajar-doctor    # no file: reads NATS_URL, AJAR_SOURCE_ID, AJAR_SIGNING_SEED
```

**Once running**, set `AJAR_HEALTH_ADDR=0.0.0.0:9090` for `GET /healthz` and
`GET /metrics` (published, skipped, publish errors). The Helm chart wires
these by default.

## Reference

### Keys

Three kinds of key material exist. All of them arrive in the packet.

1. **Your signing key.** An Ed25519 keypair. The private half signs every
   event you send; the operator registered the public half when they made
   your packet. Consumers do not have one.
2. **The operator's egress key.** Only its public half travels. It signed your
   packet, and it signs every event that passed governance, so consumers
   verify everything with this one key.
3. **Transport credentials.** A client certificate and key for the broker
   connection, plus the operator's CA certificate. These protect the pipe;
   the signing key protects the data.

If your policy says a private key must be born on your own hardware, generate
it yourself and send the operator only the public half:

```bash
scripts/gen-connector-key.sh          # or:
openssl genpkey -algorithm ed25519 -out connector.key
openssl pkey -in connector.key -pubout -outform DER | tail -c 32 | xxd -p -c 64
```

Then run `ajar-up <packet> --signing-key <file>`. Everything else is
identical. Keep the private half in a secrets manager or a file with
locked-down permissions, never in source control.

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
- The broker authenticates connectors with a client certificate. `ajar-up`
  configures it from the packet. By hand, set `AJAR_TLS_CA`, `AJAR_TLS_CERT`
  and `AJAR_TLS_KEY` and use a `tls://` broker address.

### Building for an air-gapped network

The install commands above fetch from the internet. On a connected machine,
at the release tag you intend to ship:

```bash
git clone --depth 1 --branch v0.5.10 https://github.com/promaka/ajar-connectors
cd ajar-connectors
cargo vendor vendor-crates/          # Rust
(cd go && go mod vendor)             # Go
pip download ./python -d wheels/     # Python
sha256sum -b $(git ls-files) > MANIFEST.sha256
```

Carry the directory across, verify `MANIFEST.sha256` on arrival, and build
offline with `cargo build --offline`, `go build -mod=vendor` or
`pip install --no-index --find-links wheels/`.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Rejected: signature invalid | public key not registered, wrong seed, or a `source_id` that differs from the registered one | compare the registered public key with yours; check `AJAR_SOURCE_ID` |
| Rejected: unknown attribute | an attribute the entity type does not declare | remove it, or ask the operator to add it |
| Rejected: unknown entity type | the type is not in Core's ontology | use a declared type, or get yours registered |
| Build error: unnamespaced entity type | the type is not `mim:<type>` or `x:<vendor>:<type>` | namespace it |
| Nothing arrives, no error | wrong subject or `source_id` | the subject is `ajar.ingest.<source_id>` with your assigned id |

Anything that needs a new entity type or attribute lives on the Core side.
Talk to your operator; that is the one part not in this repository.
