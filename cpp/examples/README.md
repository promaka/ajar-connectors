<!-- SPDX-License-Identifier: Apache-2.0 -->
# C++ examples

Built by the `cpp/` CMake project (see the top-level README for configure/build).

- **`cot_connector.{hpp,cpp}` + `cot_roundtrip.cpp`** — Cursor-on-Target XML
  <-> canonical event, with a `canonical → CoT → canonical` round-trip test.
- **`first_connector.cpp`** — native CoT in, signed canonical event out (the
  20-line "first connector").
- **`synthetic_radar.cpp`** — streams synthetic tracks into a local Core (below).

## synthetic_radar

Streams synthetic `mim:aircraft` tracks into a locally running **Ajar Core** so
you can watch the whole path end to end:

```
synthetic_radar ──PUB──▶ NATS ──▶ Core ──▶ accepted ──▶ Postgres + audit
   (this example)     ajar.ingest.<source>
```

Each tick (~1/sec) it advances a few tracks over the Gulf region, builds the
event with the SDK's `EventBuilder`, **seals** it, and publishes the sealed
bytes to NATS subject `ajar.ingest.<source>` via the real
[nats.c](https://github.com/nats-io/nats.c) (`cnats`) client.

> **Example only.** Signs with the seed file named by `AJAR_SIGNING_SEED`, or
> an ephemeral throwaway key when unset,
> and picks a transport (NATS). The SDK library stays transport-free — the NATS
> client is linked into this example only. The `synthetic_radar` target is built
> **only if cnats is found** (`brew install cnats`, or build nats.c from source),
> so the SDK + conformance build needs no NATS client.

### Run

```bash
# Configure + build (macOS/brew shown; OpenSSL hint only needed on macOS):
cmake -S cpp -B cpp/build -DCMAKE_PREFIX_PATH=/opt/homebrew \
      -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
cmake --build cpp/build -j

# Dry run — build + seal + print, no NATS needed (also a ctest):
./cpp/build/synthetic_radar --dry-run
./cpp/build/synthetic_radar --dry-run --ticks 3   # bounded, exits after 3 ticks

# Against a default local Core (NATS on 127.0.0.1:4222):
./cpp/build/synthetic_radar
```

Environment overrides: `NATS_URL` (default `nats://127.0.0.1:4222`),
`AJAR_SOURCE_ID` (default `demo-connector`), `AJAR_INGEST_PREFIX` (default
`ajar.ingest`).

### Why these exact choices

The defaults reach a stock local Core with **zero core changes**:

- **`source` = `demo-connector`** matches the Core's `AJAR_SOURCE_ID`, so the
  subject (`ajar.ingest.demo-connector`) is the one Core is listening on.
- **`AJAR_SIGNING_SEED`** names the seed whose public half the receiving
  registry has registered, so the sealed signature verifies. The demo stack
  mints one at startup; none lives in this repository.
- **`entity_type = "mim:aircraft"`** with a **`location`** (the seed ontology
  requires position for aircraft) and **no attributes** (the seed `mim:aircraft`
  has no attribute schema yet → any attribute is rejected as `UnknownAttribute`).
  `received_at` is left empty — Core stamps it.
- The default policy accepts anything whose `entity_type` starts with `mim:`, so
  these flow straight through to `accepted → stored + audited`.
