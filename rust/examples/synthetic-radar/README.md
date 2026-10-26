<!-- SPDX-License-Identifier: Apache-2.0 -->
# synthetic-radar (example)

Streams synthetic `mim:` tracks (aircraft, vessels and land vehicles) into a
locally running **Ajar Core** so you can watch the whole path end to end:

```
synthetic-radar ──PUB──▶ NATS ──▶ Core ──▶ accepted ──▶ Postgres + audit
   (this example)     ajar.ingest.<source>
```

Each track follows a **looping waypoint route** over the Gulf region, and the
connector emits a position for every track each sweep — building the event with
the SDK's `EventBuilder`, **sealing** it, and publishing the sealed bytes to NATS
subject `ajar.ingest.<source>`. The rate is configurable (default ~600
records/min across a fixed set of 14 tracks).

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

# Dry run — build + seal + print, no NATS and no key needed (CI-friendly):
cargo run -p synthetic-radar -- --dry-run
cargo run -p synthetic-radar -- --dry-run --ticks 3   # bounded, exits after 3 ticks

# Publish to a local Core (NATS on 127.0.0.1:4222). Publishing needs your
# connector's seed, e.g. from `scripts/gen-connector-key.sh demo-radar`:
AJAR_SIGNING_SEED=/path/to/demo-radar.seed cargo run -p synthetic-radar

# More volume, ~12000 records/min:
AJAR_SIGNING_SEED=/path/to/demo-radar.seed AJAR_RATE_PER_MIN=12000 cargo run -p synthetic-radar
```

Environment:

| Var | Default | Meaning |
|-----|---------|---------|
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS server address |
| `AJAR_SIGNING_SEED` | _(required)_ | path to the connector's Ed25519 seed (32 raw bytes or 64 hex chars); only `--dry-run` runs without it |
| `AJAR_SOURCE_ID` | `demo-radar` | connector identity; must match the `source_id` Core has registered for this key |
| `AJAR_INGEST_PREFIX` | `ajar.ingest` | subject prefix (full subject is `<prefix>.<source>`) |
| `AJAR_RATE_PER_MIN` | `600` | target records per minute (sweep interval is derived) |
| `AJAR_TLS_CA` / `AJAR_TLS_CERT` / `AJAR_TLS_KEY` | _(unset)_ | all three set → mutual TLS to NATS |
| `AJAR_HEALTH_ADDR` | _(unset)_ | serve Prometheus `/metrics` and `/healthz` on this address |

## Why these exact choices

The defaults are tuned for a local test:

- **`source` = `demo-radar`** is the identity the dev stack
  (`deploy/dev/compose.yml`) registers. Against a Core, register `demo-radar`
  with this connector's public key, or set `AJAR_SOURCE_ID` to the identity
  Core already has.
- **`AJAR_SIGNING_SEED`** names the seed whose public half the receiving
  registry (the dev sink, or Core) has registered, so the sealed signature
  verifies. The demo stack mints one at startup; none lives in this repository.
- **`entity_type`** is `mim:aircraft`, `mim:vessel` or `mim:land-vehicle` by
  domain, always with a **`location`**, and the governed attributes `hostility`
  and `callsign` (plus `vessel_domain` on vessels). `received_at` is left
  empty — Core stamps it.
- A dev-mode Core's built-in policy accepts anything whose `entity_type` starts
  with `mim:`, so these flow straight through to `accepted → stored + audited`.
  A sovereign-mode Core needs a policy rule for this connector first.
