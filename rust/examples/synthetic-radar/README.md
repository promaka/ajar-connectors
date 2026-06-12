<!-- SPDX-License-Identifier: Apache-2.0 -->
# synthetic-radar (example)

Streams synthetic `mim:aircraft` tracks into a locally running **Ajar Core** so
you can watch the whole path end to end:

```
synthetic-radar ──PUB──▶ NATS ──▶ Core ──▶ accepted ──▶ Postgres + audit
   (this example)     ajar.ingest.<source>
```

Each tick (~1/sec) it advances a few tracks over the Gulf region, builds the
event with the SDK's `EventBuilder`, **seals** it, and publishes the sealed
bytes to NATS subject `ajar.ingest.<source>`.

> ⚠️ **Example only.** This carries a **dev-only** signing seed (32 bytes of
> `0x03`) and talks NATS directly. The `ajar-connector` crate stays minimal and
> transport-free — the NATS choice lives here. To avoid bit-rotting against a
> client crate, the example speaks the NATS PUB protocol over TCP itself
> (`src/nats.rs`); a real connector would use a maintained client like
> `async-nats`.

## Run

```bash
# Dry run — build + seal + print, no NATS needed:
cargo run -p synthetic-radar -- --dry-run

# Against a default local Core (NATS on 127.0.0.1:4222):
cargo run -p synthetic-radar
```

Environment overrides:

| Var | Default | Meaning |
|-----|---------|---------|
| `NATS_URL` | `127.0.0.1:4222` | NATS server address |
| `AJAR_SOURCE_ID` | `demo-connector` | must equal the Core's `AJAR_SOURCE_ID` |
| `AJAR_INGEST_PREFIX` | `ajar.ingest` | subject prefix (full subject is `<prefix>.<source>`) |

## Why these exact choices

The defaults are tuned to reach a stock local Core with **zero core changes**:

- **`source` = `demo-connector`** matches the Core's `AJAR_SOURCE_ID`, so the
  subject (`ajar.ingest.demo-connector`) is the one Core is listening on.
- **dev seed `[0x03; 32]`** matches the Core's registered dev connector profile,
  so the sealed signature verifies. Documented test seed — never production.
- **`entity_type = "mim:aircraft"`** with a **`location`** (the seed ontology
  requires position for aircraft) and **no attributes** (the seed `mim:aircraft`
  has no attribute schema yet, so any attribute is rejected as
  `UnknownAttribute`). `received_at` is left empty — Core stamps it.
- The default policy accepts anything whose `entity_type` starts with `mim:`, so
  these flow straight through to `accepted → stored + audited`.
