<!-- SPDX-License-Identifier: Apache-2.0 -->
# synthetic-radar (example)

Streams synthetic `mim:aircraft` tracks into a locally running **Ajar Core** so
you can watch the whole path end to end:

```
synthetic-radar ──PUB──▶ NATS ──▶ Core ──▶ accepted ──▶ Postgres + audit
   (this example)     ajar.ingest.<source>
```

Each aircraft follows a **flight path** (a looping waypoint route over the Gulf
region), and the connector emits a position for every track each sweep — building
the event with the SDK's `EventBuilder`, **sealing** it, and publishing the
sealed bytes to NATS subject `ajar.ingest.<source>`. The volume is configurable;
it streams **thousands of records a minute** (default ~3000/min, 50 aircraft).

> **Example only.** This signs with the seed file named by `AJAR_SIGNING_SEED`
> (an ephemeral throwaway key in `--dry-run`) and picks a transport (NATS). The `ajar-connector` crate stays minimal
> and transport-free — the NATS client lives here, in the example. It uses the
> real [`async-nats`](https://crates.io/crates/async-nats) client (the same one
> Ajar Core uses), so it models the pattern a vendor copies.

The examples are a **separate Cargo workspace** (`rust/examples/`) so their
transport dependencies (a NATS client + async runtime) resolve independently of
the SDK crate.

## Run

```bash
cd rust/examples

# Dry run — build + seal + print, no NATS needed (and CI-friendly):
cargo run -p synthetic-radar -- --dry-run
cargo run -p synthetic-radar -- --dry-run --ticks 3   # bounded, exits after 3 ticks

# Against a default local Core (NATS on 127.0.0.1:4222):
cargo run -p synthetic-radar

# Crank the volume: 100 aircraft at ~12000 records/min:
AJAR_TRACKS=100 AJAR_RATE_PER_MIN=12000 cargo run -p synthetic-radar

# Negative test: also emit one known-bad track Ajar Core MUST reject:
cargo run -p synthetic-radar -- --inject-rejected
```

Environment overrides:

| Var | Default | Meaning |
|-----|---------|---------|
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS server address |
| `AJAR_SOURCE_ID` | `demo-connector` | must equal the Core's `AJAR_SOURCE_ID` |
| `AJAR_INGEST_PREFIX` | `ajar.ingest` | subject prefix (full subject is `<prefix>.<source>`) |
| `AJAR_TRACKS` | `50` | number of aircraft on flight paths |
| `AJAR_RATE_PER_MIN` | `3000` | target records per minute (sweep interval is derived) |
| `AJAR_INJECT_REJECTED` | _(unset)_ | if set (or `--inject-rejected`), also emit one known-bad track Core must reject |

## Negative test: a track Ajar must reject

`--inject-rejected` (or `AJAR_INJECT_REJECTED=1`) adds **one** extra track
(`RJX-666`) each sweep: a well-formed, validly **signed** `mim:aircraft` that
carries an **undeclared attribute**. The signature is valid, so this isolates
Core's *ontology/validation* boundary — Core must reject it as `UnknownAttribute`
while the 50 good tracks flow through to `accepted`. It's a boundary test: if any
of these are ever **accepted**, that's the vulnerability. Watch Core's audit /
reject log for steady `RJX-666` rejections. Off by default so the normal demo
stays clean.

## Why these exact choices

The defaults are tuned to reach a stock local Core with **zero core changes**:

- **`source` = `demo-connector`** matches the Core's `AJAR_SOURCE_ID`, so the
  subject (`ajar.ingest.demo-connector`) is the one Core is listening on.
- **`AJAR_SIGNING_SEED`** names the seed whose public half the receiving
  registry (the dev sink, or Core) has registered, so the sealed signature
  verifies. The demo stack mints one at startup; none lives in this repository.
- **`entity_type = "mim:aircraft"`** with a **`location`** (the seed ontology
  requires position for aircraft) and **no attributes** (the seed `mim:aircraft`
  has no attribute schema yet, so any attribute is rejected as
  `UnknownAttribute`). `received_at` is left empty — Core stamps it.
- The default policy accepts anything whose `entity_type` starts with `mim:`, so
  these flow straight through to `accepted → stored + audited`.
