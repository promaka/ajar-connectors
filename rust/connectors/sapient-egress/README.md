<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-sapient-egress — Ajar as a SAPIENT sensor node

Egress connector for **SAPIENT** (BSI Flex 335). Ajar registers with the
customer's fusion node as one more sensor node and carries governed events to
it as detection reports: feeds SAPIENT never had, such as MAVLink drones,
ADS-B, AIS or a radar's ASTERIX, arrive on the fusion node as tracks from a
node called Ajar.

What the fusion node receives is what Core's policy released onto governed
egress, with the sovereign's marking. Every envelope is verified under Core's
egress key before it is mapped; nothing that fails reaches the fusion node.

## Model

```
NATS ajar.egress.signed.> ──▶ ajar-sapient-egress ──TCP──▶ fusion node
  (sealed by Core)          verify + map + register      (sees a SAPIENT node)
```

## What it sends

| When | Message |
|---|---|
| On every connection | a `Registration`: node type, ICD version, a capability, the status interval, one permanent mode stating the coordinate and velocity units every report uses, a task definition, make and model. The node reports nothing until the fusion node acknowledges it. |
| Every `status_interval_s` | a `StatusReport`: system OK, the mode, this node's position if configured. Not buffered: a stale heartbeat says nothing true. |
| Per released event with a position | a `DetectionReport`: WGS-84 position in degrees and metres, ENU velocity in m/s from `speed`, `course` and `vertical_rate`, a classification, the event's confidence, the native identifier, and the Ajar source, event id, type and hostility as object information. |
| On a task from the fusion node | a `TaskAck` refusing it: this node relays governed events and cannot be pointed, moved or re-thresholded. |

An event's object identifier stays the same across reports, so the fusion
node sees a track, not a scatter of detections. Events without a position are
counted and not sent; a detection report has to place its object.

**Classification.** An event's own `sapient_classification` or `object_class`
attribute is reported as is. Otherwise the entity type decides: `mim:aircraft`
is `Aircraft`, `mim:vessel` is `Vessel`, `mim:land-vehicle` is `Vehicle`,
`mim:person` is `Person`, and so on; `[sapient.classification]` adds or
overrides, and `default_classification` covers the rest.

## Configure and run

```sh
cp sapient-egress.example.toml sapient-egress.toml   # edit nats_url, the key, [sapient]
ajar-sapient-egress ./sapient-egress.toml
```

Set `AJAR_HEALTH_ADDR=0.0.0.0:9090` for `/healthz` and `/metrics`: delivered,
rejected, deduplicated, unlocated and gap-dropped counts, status reports sent,
tasks refused, reconnections, registrations the fusion node rejected, and a
link-up gauge.

**Resilience.** Reports are buffered up to `buffer_max` while the fusion
node is unreachable, oldest dropped and counted beyond that, and delivered in
order when the link returns. The link reconnects and re-registers by itself; a
rejected registration is logged with the fusion node's reasons and retried.

**Onboarding.** The operator issues a consumer identity, with a
subscribe-only certificate, as for the TAK egress:

```sh
ajar onboard sapient-out-1 --consumer --egress-scope signed ...
```

The connector reads the signed channel, `ajar.egress.signed.>`, where Core
publishes each released event sealed under the egress key; the rendering
subjects carry plain CoT and GeoJSON and will not verify. Core publishes
the signed channel from release 0.1.28.

The packet's `egress_verifying_key_hex` and `nats_url` go into the config.

## Fusion node compatibility

The registration carries every field BSI Flex 335 marks mandatory. A fusion
node product may require particular capability strings or a specific node
type; those are set in one place, `src/report.rs`, and surfaced in the
rejection's reasons when a fusion node refuses them. Built against BSI Flex
335 v2.0; v1.0 is a build-time choice in the wire crate.

## Conformance

`cargo test -p ajar-sapient-egress` proves a governed event becomes a located,
classified detection report with the standard's identifiers and velocity
units, that the registration carries every mandatory field and survives the
wire, that a fusion node's rejection is surfaced with its reasons, that a
dropped connection re-registers on the next send and a task is refused, and
that the buffer bounds memory and counts what it drops.
