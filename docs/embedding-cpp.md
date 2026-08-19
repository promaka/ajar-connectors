<!-- SPDX-License-Identifier: Apache-2.0 -->
# Embedding the Ajar SDK — C++

For linking Ajar into your own binary. If you want a ready-made connector for a
standard format instead, see [CONNECTORS.md](../CONNECTORS.md).

## Get it

One self-contained tarball, attached to every release with a SHA-256 and signed
build provenance. It carries the vendored contract, so the extracted tree builds
on its own — nothing else from this repository is needed.

```bash
curl -LO https://github.com/promaka/ajar-connectors/releases/download/v0.5.3/ajar-connector-cpp-0.5.3.tar.gz
curl -LO https://github.com/promaka/ajar-connectors/releases/download/v0.5.3/ajar-connector-cpp-0.5.3.tar.gz.sha256
sha256sum -c ajar-connector-cpp-0.5.3.tar.gz.sha256

tar xzf ajar-connector-cpp-0.5.3.tar.gz && cd ajar-connector-cpp-0.5.3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
cmake --install build --prefix /opt/ajar
```

Then from your own project:

```cmake
find_package(ajar_connector REQUIRED)
target_link_libraries(your_service PRIVATE ajar_connector::ajar_connector)
```

Requires CMake 3.20, a C++17 compiler and `protoc`.

## Build, seal, publish

```cpp
#include <ajar/connector.hpp>

auto key = ajar::SigningKey::from_seed(seed);   // your 32-byte Ed25519 seed

auto event = ajar::EventBuilder("acme-radar-1", "mim:aircraft")
    .new_id()                          // fresh UUIDv7 per event
    .now()                             // RFC 3339 observation time
    .location(25.27, 51.52, 10600.0)   // lat, lon, altitude in metres
    .attribute("speed", "231.50")      // governed: m/s
    .metadata("icao", "4CA2D6")        // ungoverned: native identity
    .payload(raw_frame)                // your source bytes, verbatim
    .build();

auto sealed = ajar::seal(ajar::canonical_bytes(event), key);
publish("ajar.ingest.acme-radar-1", sealed);   // your NATS client
```

The SDK builds, seals and verifies. Transport is yours.

## What the two identifiers mean

**`source_id`** is your registered identity. Ajar accepts an event only if its
seal verifies under the public key registered against this exact string.

**The signing key** is a 32-byte Ed25519 seed you generate and never share:

```bash
scripts/gen-connector-key.sh acme-radar-1
```

The private seed stays in your secret store; only the public half is sent.

## Governed versus ungoverned

`attribute()` is validated against Ajar's ontology; `metadata()` is not and is
always accepted.

**Ajar discards an unrecognised attribute name or value without an error.** Your
service keeps running and the data does not arrive. Agree the entity type and
attribute names with your operator before you build, and treat controlled
vocabularies as case-sensitive — `hostility` takes `Friend`, not `friendly`.
Native identifiers go in `metadata`, never in `id`.

Full reference: [ATTRIBUTES.md](../rust/connectors/ATTRIBUTES.md).

## Getting registered

Send your operator your `source_id`, the entity-type prefixes you will emit, and
your **public** key. You receive confirmation plus the NATS endpoint and
credentials. Your source never leaves your environment.

## Proving your bytes

The tarball ships its own gate — this is the same check CI runs before the
tarball is released:

```bash
./build/conformance
```

To prove *your* build, offline and with no Ajar Core:

```bash
ajar-conformance run --impl ./your-adapter
```

See [`cpp/examples/connector_template.cpp`](../cpp/examples/connector_template.cpp)
for a runnable starting point.

## Constrained targets

For MCUs and similar, [`cpp/embedded/`](../cpp/embedded/) builds the same
contract against nanopb.

## The contract

One page: [docs/wire-contract-v1.md](wire-contract-v1.md).
