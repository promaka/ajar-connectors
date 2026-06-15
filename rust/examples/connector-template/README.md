<!-- SPDX-License-Identifier: Apache-2.0 -->
# connector-template — copy me

The minimal starting point for a new Ajar connector. **Two edits and you're done.**

## Try it in 10 seconds (no key, no NATS, no feed)

```bash
cd rust/examples
echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
  | cargo run -p connector-template -- --dry-run
# -> 019e... -> ajar.ingest.demo-connector (203 sealed bytes)  [dry-run]
```

You just built, signed, and (dry-run) "sent" a canonical Ajar event.

## Make it yours — the whole job

Open [src/main.rs](src/main.rs) and edit the two clearly-marked blocks:

1. **`EDIT 1`** — describe one record from your feed (the struct fields).
2. **`EDIT 2`** — map that record into an `Event` (position, time, type…).

That's ~15 lines. Everything below the line in the file (connect, sign, publish,
key loading) you leave alone.

If your feed isn't newline-JSON, swap the one stdin reader for your TCP socket /
file / API / serial port — the rest is unchanged.

## Run it for real

```bash
# 1. Generate your key (once). Sends you a public hex to register with Ajar:
../../scripts/gen-connector-key.sh acme-radar

# 2. Run, pointed at the NATS endpoint Ajar gave you:
AJAR_SIGNING_SEED=acme-radar.seed \
AJAR_SOURCE_ID=acme-radar-1 \
NATS_URL=tls://nats.you.mil:4222 \
cargo run -p connector-template
```

| Env var | Meaning |
|---|---|
| `AJAR_SIGNING_SEED` | path to your 32-byte key seed (from the keygen script) |
| `AJAR_SOURCE_ID` | the id Ajar assigned you |
| `NATS_URL` | the endpoint Ajar gave you (`tls://…`, `wss://…:443`, …) |
| `AJAR_INGEST_PREFIX` | subject prefix (default `ajar.ingest`) |

See the full [onboarding guide](../../../ONBOARDING.md) for the data flow,
deployment topology, and troubleshooting.
