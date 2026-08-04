<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-gmti — STANAG 4607 (NATO GMTI) connector

Ingests **GMTI** (Ground Moving Target Indicator) radar packets and turns each
moving-target detection into a signed canonical Ajar event.

Alongside [`klv`](../klv), this is a repo **reference binary-STANAG connector** —
a worked example of an **existence-mask-driven** binary format (see the top-level
[`AGENTS.md`](../../../AGENTS.md)).

## What it decodes

A GMTI packet is a 32-byte header + a run of segments. The connector decodes the
**Dwell Segment** (type 2) — where the moving targets live — completely:

- **Packet header**: platform id, job id, edition.
- **Dwell**: the 8-byte existence mask, the dwell-level geometry (sensor lat/lon,
  dwell-area centre, lat/lon scale factors), and the target report count.
- **Per target report**: position (absolute hi-res lat/lon, or delta-from-centre
  × scale factor), geodetic height, line-of-sight (radial) velocity, SNR,
  classification code, RCS.

Other segment types (Mission, Job Definition, HRR, ...) are skipped.

## Losslessness

The **entire raw dwell segment** is sealed verbatim into every target event's
`Event.payload`. Any dwell or target field the connector does not map is
preserved for a later ontology (or a generated parser extension) to extract.

## Identity — detections, not tracks

GMTI target reports are **un-associated detections**: the format carries no
persistent per-target id. So `source_uid` is unique **per detection** —
`<platform>:<job_id>:<dwell_index>:<mti_report_index>` — not a track. Downstream
fusion/tracking correlates detections across dwells. Do not expect a GMTI
`source_uid` to persist for the same physical vehicle between dwells.

## Units

Angles use the STANAG 4607 binary-angle scaling (SA32 → ±90°, BA32 → 0–360°,
normalised to ±180°). Radial velocity is normalised **cm/s → m/s** and emitted as
`radial_velocity` (line-of-sight, distinct from ground `speed`). Geodetic height
is metres.

## Timestamp

GMTI dwell time is milliseconds **relative to the Mission Segment reference
time**, which may not be in the same packet, so the event is stamped with
**receipt time** and the native `dwell_time_ms` is kept in metadata. Absolute
time from the Mission Segment reference is a future enhancement.

## Entity type

Emits `mim:ground-track`. If your Core ontology names ground moving-target
detections differently, change the one `entity_type` constant in `src/gmti.rs`.

## Provenance of the field layout

Field order, sizes, existence-mask bit assignments, and scale factors were taken
from the STANAG 4607 spec and cross-checked against the Wireshark dissector and
the pentlandedge `s4607` reference implementation. Known open questions (Δ-lat/lon
angular LSB, RCS dB vs half-dB) are handled conservatively and noted in the code;
validate against a real capture from your radar before production.

## Run it

```sh
cp gmti.example.toml gmti.toml   # edit source_id, key path, [transport]
ajar-gmti ./gmti.toml
```
