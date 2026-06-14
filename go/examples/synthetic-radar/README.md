<!-- SPDX-License-Identifier: Apache-2.0 -->
# synthetic-radar (Go example)

Streams synthetic `mim:aircraft` tracks into a locally running **Ajar Core** so
you can watch the whole path end to end:

```
synthetic-radar ──PUB──▶ NATS ──▶ Core ──▶ accepted ──▶ Postgres + audit
   (this example)     ajar.ingest.<source>
```

Each tick (~1/sec) it advances a few tracks over the Gulf region, builds the
event with the SDK's `EventBuilder`, **seals** it, and publishes the sealed
bytes to NATS subject `ajar.ingest.<source>` via the real
[`nats.go`](https://github.com/nats-io/nats.go) client.

> ⚠️ **Example only.** Carries a **dev-only** signing seed (32 bytes of `0x03`)
> and picks a transport (NATS). The `ajarconnector` package stays minimal and
> transport-free — the NATS client lives here. The examples are a **separate Go
> module** (`go/examples/`, with `replace … => ../`) so `nats.go` never lands in
> the SDK module's `go.mod`.

## Run

```bash
cd go/examples

# Dry run — build + seal + print, no NATS needed (and CI-friendly):
go run ./synthetic-radar -dry-run
go run ./synthetic-radar -dry-run -ticks 3   # bounded, exits after 3 ticks

# Against a default local Core (NATS on 127.0.0.1:4222):
go run ./synthetic-radar
```

Environment overrides:

| Var | Default | Meaning |
|-----|---------|---------|
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS server URL |
| `AJAR_SOURCE_ID` | `demo-connector` | must equal the Core's `AJAR_SOURCE_ID` |
| `AJAR_INGEST_PREFIX` | `ajar.ingest` | subject prefix (full subject is `<prefix>.<source>`) |

## Why these exact choices

The defaults reach a stock local Core with **zero core changes**:

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
