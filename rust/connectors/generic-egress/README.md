<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-generic-egress

Governed events out of Ajar, delivered to your system as JSON in your field
names. The egress counterpart of [`ajar-generic`](../generic): a mapping, no
code.

```
Ajar Core ──▶ ajar.egress.<format>.<source> ──▶ verify Core's egress signature ──▶ map ──▶ HTTP POST
              (governed, re-signed by Core)      (mandatory, no off switch)              (your endpoint)
```

## What arrives at your endpoint

One POST per event, one JSON object per POST, shaped by your `[mapping]`. Three
fields are present in every object no matter what the mapping says — a mapping
can rename them, never remove them:

| Always present | Default name | Content |
|---|---|---|
| Event identity | `event_id` | dedupe on this; delivery is at-most-once today, gap-possible, and becomes at-least-once when the durable leg lands |
| Markings | `policy_tags` | classification and releasability, exactly as governed |
| Governance | `governance` | `{"egress_signature": "verified"}` — set by verification, not configuration |

Governed content your mapping does not name is delivered under `unmapped`, or
refused per event with `unmapped = "refuse"`. Silent dropping does not exist:
a config file cannot strip markings off a track on its way out.

## Verification is not optional

Every payload is verified under Core's egress key (from your operator's
handover pack) before it is mapped or delivered. A payload that does not verify
is counted in `egress_rejected_total` and never leaves. There is no
`verify = false`; `--dry-run` without a key prints payload sizes under an
UNVERIFIED banner and nothing else.

Producer signatures do not survive egress by design — payload drops on all
egress and identity may drop cross-coalition, so the producer's signature would
be over bytes that no longer exist. Provenance at the consumer is Core's egress
signature; full lineage to the original sealed envelope lives in Ajar's audit
chain.

## Delivery semantics, honestly

At-most-once on the live leg: a bounded in-memory buffer, oldest dropped and
counted (`egress_gap_dropped_total`) when your endpoint is unreachable past its
attempts. Make your endpoint idempotent on `event_id` now: redeliveries become
normal when the JetStream-backed durable leg upgrades the guarantee to
at-least-once, and duplicates within one connector run are already suppressed
(`egress_deduped_total`).

## The cue channel is out of reach

Subscriptions must sit under `ajar.egress.`. The effector cue channel
(`ajar.cue.>`) is refused at config validation — structurally, then again
explicitly — so a track-share tool cannot be one wildcard away from fire
commands. This is tested, not just written.

## Run

```bash
ajar-generic-egress ./generic-egress.toml
ajar-generic-egress --dry-run ./generic-egress.toml   # print, don't POST
```

Copy [`generic-egress.example.toml`](generic-egress.example.toml). Health and
counters via `AJAR_HEALTH_ADDR` as on every connector.
