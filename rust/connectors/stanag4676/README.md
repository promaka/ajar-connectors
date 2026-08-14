<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-stanag4676

Ingress connector for **STANAG 4676** (NATO ISR Tracking Standard, AEDP-12
Edition B) — the **fused track layer** of the ISR picture. A tracker associates
observations over time into tracks with a stable identity; this connector decodes
those `nitsRoot` track messages into canonical Ajar tracks, seals each with the
connector's Ed25519 key, and publishes to Core.

It is the natural complement to [`ajar-gmti`](../gmti): GMTI gives you the raw,
un-associated detections (a fresh id every dwell); 4676 gives you the recognised
tracks with a **persistent id** for the same object across time. Detections and
tracks — the two layers of the ground/air picture.

## Model

```
STANAG 4676 XML ──▶ ajar-stanag4676 ──▶ canonical Event(s) ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
   untrusted edge      decode              (one per track point)  (Ed25519)      (mTLS to Core)
```

One `nitsRoot` message carries **many tracks, each with many track points**, so one
frame produces several sealed events — one per track point. The raw `<track>`
element is sealed verbatim into `Event.payload`, so nothing the decoder does not yet
map is lost. The connector holds no Core secrets — only its own signing key. See
[HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## What it decodes, and the traps it gets right

There are no `latitude`/`longitude`/`speed`/`heading` elements in 4676 — the
load-bearing facts are packed in ways a naive decoder mishandles:

| Fact | Where it lives | What this connector does |
|---|---|---|
| **Stable id** | `track/uid` — Base64 of a raw 16-byte UUID | decodes + formats to the canonical UUID → `source_uid` |
| **Position** | `<pos>` under `<dynamics cs="WGS_84">`, as `lat lon height-m` | geographic fix only when `cs` is WGS-84; other systems ride as metadata, never mis-projected |
| **Velocity** | `<vel>`, whose WGS-84 horizontal components are **degrees/second** | derives ground `speed` (m/s) + `course` (deg); keeps the native °/s in metadata |
| **Time** | `baseTime + relTime × relTimeIncrement` (no ISO stamp on the point) | reconstructs the absolute RFC 3339 time |
| **Status** | `segment/status` | maps INITIATING/MAINTAINING/SEARCHING/TERMINATED → new/update/coast/drop |
| **Identity** | `track/object/id1241` (STANAG 1241) | hostility, mapping one-to-one onto MIM including AssumedFriend and Suspect |
| **Environment** | `id1241/environment` | an attribute, not the entity type: see below |
| **Classification** | `originatorConfidentialityLabel` (STANAG 4774) | surfaced as the event's `policy_tag` |

Matching is on **local element names only**, so any namespace-prefix binding
(`ns2:`, `foo:`, default) decodes identically. Decoded fields ride as attributes
with canonical units (`speed` m/s, `course` deg, `vertical_rate` m/s per ADR-0019);
native values are preserved in metadata.

> **Affiliation is conservative.** Only FRIEND/HOSTILE/NEUTRAL assert an
> hostility; ASSUMED_FRIEND, SUSPECT, and UNKNOWN resolve to the operator default
> (else `unknown`) so a COP never shows a fabricated friend or hostile — the precise
> STANAG 1241 identity is always preserved for a downstream rule to use.

**Every track is `mim:object`.** The `environment` field reports a domain, not a
classification: AIR says a track is in the air, not that it is an aircraft, and it
could as easily be a missile, a balloon or a bird. Choosing a specific type from it
would assert something the tracker never said, so the domain rides as an attribute
and the type stays honest. Core drives the CoT battle dimension from that
attribute, so an air contact still reaches TAK in the air dimension as `a-u-A`
rather than as a bare unknown. The wire value is normalised first: STANAG 1241
hyphenates `SUB-SURFACE` where Core's closed set does not, and an unrecognised
token becomes `UNKNOWN` with the original kept in `environment_source`. A specific type belongs to `objectClass`, an APP-6 code
that genuinely does classify; mapping APP-6 onto MIM is separate work. A deployment
that knows its feed better can override per environment in `[entity_map]`.

**Scope.** This connector decodes the **track** layer (`track → segment → tp`).
Detection-only messages (raw GMTI dots re-embedded in 4676) produce no events — use
`ajar-gmti` for those. Non-WGS-84 coordinate systems (ECEF, local Cartesian) are
preserved as metadata rather than projected; the raw XML is sealed regardless, so a
later pass can extend coverage without touching the wire.

## Framing

A 4676 message is a whole XML document, so the transport must deliver **one complete
message per frame**. The two clean options:

- **`tcp-server` / `tcp-client` with `framing = "length-delimited"`** — each message
  prefixed with its 2-byte length (the recommended stream integration); or
- any line transport (`file`, `dir`, `stdin`, `exec`) when the producer emits
  **one message per line** (compact, single-line XML).

Pretty-printed multi-line XML over a line transport will not frame correctly — use
length-delimited framing for that.

## Configure & run

Copy [`stanag4676.example.toml`](stanag4676.example.toml):

```toml
source_id = "isr-tracker-1"
nats_url  = "nats://127.0.0.1:4222"
signing_key_path = "/etc/ajar/isr-tracker-1.key"

[transport]
kind = "tcp-server"
bind = "0.0.0.0:4676"
framing = "length-delimited"
```

```bash
ajar-stanag4676 ./stanag4676.toml
# production mTLS + health as per the repo README
```

## Security note

4676 is an untrusted edge and the decoder walks attacker-influenced XML — arbitrary
namespace prefixes, truncated elements, positions that lie, Base64 that is not, and
a `relTime × increment` that can overflow the clock. Every conversion is bounds- and
overflow-checked; the decoder never panics and never emits a misaligned or fabricated
position. Trust is established downstream by the seal.

## Conformance

`cargo test` decodes a hand-built WGS-84 air track (position, derived kinematics,
identity carried from the `object` block that follows the points in document order —
proving the deferred per-track flush), reconstructs the point time from
`baseTime + relTime`, checks the event against Core's content contract and that the
seal verifies under the published contract key, and fuzzes the decode against
thousands of arbitrary and track-shaped inputs (never panics). The field model is
cross-checked against the `bradh/jim` Edition-B reference implementation and its
sample messages; the fixtures shipped here are clean-room, authored for these tests.
