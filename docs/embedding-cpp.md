<!-- SPDX-License-Identifier: Apache-2.0 -->
# Embedding the Ajar SDK — C++

For linking Ajar into your own binary. If you want a ready-made connector for a
standard format instead, see [CONNECTORS.md](../CONNECTORS.md).

## What you do, in order

| Step | You do | Time |
|---|---|---|
| **1** | [Download and build the SDK](#1-download-and-build) | 5 min |
| **2** | [Map your feed to MIM](#2-map-your-feed) | the real work |
| **3** | [Get registered](#3-get-registered) | one exchange with your operator |
| **4** | [Publish over mTLS](#4-publish) | your NATS client |

Steps 1 and 4 are mechanical. Step 2 is the only part that needs thought, and
step 3 is the only part that needs us.

---

## 1. Download and build

One tarball. It carries the contract inside it, so you need CMake, a C++17
compiler and `protoc`, and nothing else from us.

```bash
curl -LO https://github.com/promaka/ajar-connectors/releases/download/v0.5.9/ajar-connector-cpp-0.5.9.tar.gz
curl -LO https://github.com/promaka/ajar-connectors/releases/download/v0.5.9/ajar-connector-cpp-0.5.9.tar.gz.sha256
sha256sum -c ajar-connector-cpp-0.5.9.tar.gz.sha256

tar xzf ajar-connector-cpp-0.5.9.tar.gz && cd ajar-connector-cpp-0.5.9
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
```

Prove it before you write anything:

```bash
./build/conformance          # -> all conformance vectors reproduced
```

That is the acceptance test. Green means your build produces exactly the bytes
Ajar accepts. Then install it:

```bash
cmake --install build --prefix /opt/ajar
```

and link it:

```cmake
find_package(ajar_connector REQUIRED)
target_link_libraries(your_service PRIVATE ajar_connector::ajar_connector)
```

The libraries are static, so they link into your binary. Nothing to deploy
alongside it.

---

## 2. Map your feed

**The SDK does not do this for you.** It builds, signs and enforces structure. It
does not know that your `TrackType=3` is an aircraft, or that your speed is in
knots and must be metres per second. A wrong entity type or attribute name
compiles, seals and publishes, and Ajar discards it without an error.

Read **[docs/mapping-to-mim.md](mapping-to-mim.md)**. It has a complete file you
can copy: your record struct in, sealed event out, with the type mapping, the
unit conversions and the exact vocabularies.

**Validate against the ontology your operator sends you** —
`ontology-mim-5.3-conformant-1.json`. That file is the contract your events are
checked against: it lists the entity types and attribute names that exist, and
anything outside it is discarded silently. If you have not got it, ask before you
write the mapping.

Four decisions, per record:

1. **Entity type** — your class to `mim:aircraft`, `mim:vessel`, `mim:sensor`, or
   `mim:object` when you do not know.
2. **Units** — `speed` and `vertical_rate` in m/s, `course` in degrees, altitude
   in metres. Keep your native values in `metadata`.
3. **Vocabularies** — `hostility` is `Friend`, not `friendly`. Case is exact.
4. **Identity** — your track id goes in `metadata`, never the event id.

Anything you are unsure about goes in `metadata`, which is ungoverned and always
kept.

**Check your mapping before you run it.** The SDK validates a mapping, or a
built event, against the vendored ontology — offline, from the tarball:

```cpp
for (const auto& fault : ajar::validate(event))
  std::fprintf(stderr, "%s\n", fault.message().c_str());
```

The connector template wires this to a flag, so your CI can hold the mapping to
the contract:

```bash
./build/connector_template --check   # exit 0 clean, 1 with each fault named
```

Validation is advisory: it refuses nothing per event. Refusing to start on
faults is your call at your own initialisation, and the right one for a service
that would otherwise publish events Ajar discards silently.

---

## 3. Get registered

Ajar accepts events only from a registered identity.

**Generate your key.** The private half never leaves your machine:

```bash
openssl genpkey -algorithm ed25519 -out connector.key
openssl pkey -in connector.key -outform DER | tail -c 32 > connector.seed
openssl pkey -in connector.key -pubout -outform DER | tail -c 32 | xxd -p -c 64
```

The last line prints your public key. **Send your operator:**

- your `source_id` (e.g. `acme-1`)
- the entity types you will emit (e.g. `mim:aircraft`, or the `x:` prefix)
- that public key hex

**They send back:** confirmation, the NATS endpoint, your client certificate and
the CA.

---

> **Permissions.** If you run in a container as a non-root user, make sure the
> TLS key and the signing seed are readable by that user. A key mounted `0600`
> under a different owner gives a TLS failure with no network round trip and only
> a handshake EOF in the server log, which is easy to mistake for a network or
> certificate problem.

## 4. Publish

The SDK seals; you publish. There is no NATS client in the C++ library, so use
your own.

```cpp
auto sealed = ajar::seal(ajar::canonical_bytes(event), key);
publish("ajar.ingest.acme-1", sealed);
```

Subject is `ajar.ingest.<source_id>`. Production is mTLS: your client certificate
is your transport identity, and its CN must match your `source_id`.

**Done.** Your events are sealed, accepted and audited.

---

## What the two identifiers mean

**`source_id`** is your registered identity. Ajar accepts an event only if its
seal verifies under the public key registered against this exact string.

**The signing key** is a 32-byte Ed25519 seed. It is not your TLS key: the seed
signs events, the certificate authenticates the connection. You need both, and
they are different files.

## Key format

The signing seed is 32 raw bytes or 64 hex characters. The **TLS client key** is
separate and must be **PKCS#8** (`-----BEGIN PRIVATE KEY-----`). Convert a SEC1
EC key first:

```bash
openssl pkcs8 -topk8 -nocrypt -in client-sec1.key -out client.key
```

Certificates may be RSA or EC; P-256 with TLS 1.3 is typical.

## Proving your bytes

`./build/conformance` proves the SDK build. To prove *your* mapping code end to
end, offline and with no Ajar Core:

```bash
ajar-conformance run --impl ./your-adapter
```

## Consuming egress: governed events into your binary

The same envelope, the other direction: Core re-signs every event that passes
governance, and you verify it with the egress key from your operator's handover
pack. One function is the whole trust check:

```cpp
// Subscribe with your own NATS client to ajar.egress.<format>.>   (NEVER
// ajar.cue.> — effector cues are a separate channel by hard rule.)
static bool egress_subject_ok(const std::string& s) {
  return s.rfind("ajar.egress.", 0) == 0;
}

void on_message(const std::vector<std::uint8_t>& sealed) {
  static std::set<std::string> seen;                     // dedupe on event id
  const auto canonical = ajar::verify(sealed, kEgressKey);
  if (!canonical) return;                                // count it; never use it
  ajar::Event event;
  event.ParseFromString(*canonical);
  if (!seen.insert(event.id()).second) return;           // redelivery is normal
  handle(event);                                         // markings included
}
```

Three rules, and you are done:

1. **Verify before use, no exceptions.** A payload that fails `verify()` is
   counted and dropped, never parsed as data.
2. **Dedupe on `event.id()`.** Delivery today is at-most-once and gap-possible;
   the durable leg upgrades it to at-least-once, making redelivery normal.
3. **Never subscribe `ajar.cue.>`.** Track-sharing and effector cues are
   deliberately separate channels.

Measured on one core (release build, this SDK): ~11,700 verifies/sec — about a
million events every 90 seconds per core, and verification of distinct events
parallelises linearly.

## Constrained targets

For MCUs and similar, [`cpp/embedded/`](../cpp/embedded/) builds the same
contract against nanopb.

## The contract

One page: [docs/wire-contract-v1.md](wire-contract-v1.md).
