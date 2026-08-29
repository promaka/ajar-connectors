<!-- SPDX-License-Identifier: Apache-2.0 -->
# Embedding the Ajar SDK — Python

For linking Ajar into your own service. If you want a ready-made connector for a
standard format instead, see [CONNECTORS.md](../CONNECTORS.md).

```bash
pip install ajar-connector
```

## Build, seal, publish

```python
from ajar_connector import EventBuilder, canonical_bytes, seal, SigningKey

key = SigningKey.from_seed(open("acme-radar-1.seed", "rb").read())

event = (
    EventBuilder("acme-radar-1", "mim:aircraft")   # source_id, ontology class
    .new_id()                                       # fresh UUIDv7 per event
    .now()                                          # RFC 3339 observation time
    .location(25.27, 51.52, 10600.0)                # lat, lon, altitude in metres
    .attribute("speed", "231.50")                   # governed: m/s
    .metadata("icao", "4CA2D6")                     # ungoverned: native identity
    .payload(raw_frame)                             # your source bytes, verbatim
    .build()
)

sealed = seal(canonical_bytes(event), key)          # 64-byte signature ++ canonical
await nats.publish(f"ajar.ingest.acme-radar-1", sealed,
                   headers=ingest_headers(event))  # broker-side dedupe
```

That is the whole SDK surface for ingress: build, seal, publish.

## What the two identifiers mean

**`source_id`** is your registered identity. Ajar accepts an event only if its
seal verifies under the public key registered against this exact string, so it is
not a label you choose per event — it is who you are.

**The signing key** is a 32-byte Ed25519 seed you generate and never share:

```bash
scripts/gen-connector-key.sh acme-radar-1
```

It writes the private seed and prints the public half. The private seed stays in
your secret store; only the public half is ever sent.

## What to map to

The SDK builds and signs; deciding that your record is a `mim:aircraft` and that
your speed must be metres per second is yours. The entity types, governed
attribute names, units and controlled vocabularies are in
**[docs/mapping-to-mim.md](mapping-to-mim.md)**. Read it before you write the
mapping: a wrong type or a misspelled attribute compiles, seals and publishes,
and is then discarded without an error.

## Governed versus ungoverned

`attribute()` is validated against Ajar's ontology. `metadata()` is not, and is
always accepted.

**Ajar discards an unrecognised attribute name or value without an error.** Your
service keeps running, events keep publishing, and the data does not arrive. So:
agree the entity type and attribute names with your operator before you build,
and treat controlled vocabularies as case-sensitive — `hostility` takes `Friend`,
not `friendly`. Native identifiers go in `metadata`, never in `id`.

Full reference: [ATTRIBUTES.md](../rust/connectors/ATTRIBUTES.md).

## Key format

The signing seed is 32 raw bytes or 64 hex characters, and is not affected by
this. The **TLS client key** is: supply it as **PKCS#8** (`-----BEGIN PRIVATE
KEY-----`). Convert a SEC1 EC key (`-----BEGIN EC PRIVATE KEY-----`) first:

```bash
openssl pkcs8 -topk8 -nocrypt -in client-sec1.key -out client.key
```

The certificate itself may be RSA or EC; P-256 with TLS 1.3 is what a sovereign
bus typically presents.

> **Permissions.** If you run in a container as a non-root user, make sure the
> TLS key and the signing seed are readable by that user. A key mounted `0600`
> under a different owner gives a TLS failure with no network round trip and only
> a handshake EOF in the server log, which is easy to mistake for a network or
> certificate problem.

## Getting registered

Ajar accepts events only from a registered identity. Send your operator the
profile document — `source_id`, the entity-type prefixes you will emit, and your
**public** key:

```json
{
  "contract": "v1",
  "source_id": "acme-radar-1",
  "allowed_entity_types": ["mim:"],
  "max_payload_bytes": 65536,
  "verifying_key_hex": "e28a89…"
}
```

You receive confirmation plus the NATS endpoint and credentials. Your source code
never leaves your environment.

## Consuming egress: governed events into your service

The same envelope, the other direction: Core re-signs every event that passes
governance, and you verify with the egress key from your operator's handover
pack — the same `verify()` you already have:

```python
from ajar_connector import Event, verify

EGRESS_KEY = bytes.fromhex(open("egress.pub").read().strip())  # handover pack
seen = set()                                                    # dedupe on id

async def on_message(msg):        # your NATS subscription: ajar.egress.<fmt>.>
    try:
        canonical = verify(msg.data, EGRESS_KEY)
    except Exception:
        return                    # count it; never parse an unverified payload
    event = Event(); event.ParseFromString(canonical)
    if event.id in seen:
        return                    # redelivery is normal on the durable leg
    seen.add(event.id)
    handle(event)                 # markings included
```

Three rules: verify before use, dedupe on `event.id`, and **never subscribe
`ajar.cue.>`** — effector cues are a separate channel by hard rule.

## Proving your bytes

Before you go live, prove your build produces the bytes Ajar accepts. Offline, no
credentials, no Ajar Core:

```bash
ajar-conformance run --impl python3 your_adapter.py
```

The adapter is three lines — see
[`python/examples/conformance_adapter.py`](../python/examples/conformance_adapter.py).
Green means conformant with `contract-v1`. Put it in your CI.

## The contract

One page: [docs/wire-contract-v1.md](wire-contract-v1.md). It is the whole
agreement — event shape, canonical bytes, the seal, the subject, and what is
frozen.
