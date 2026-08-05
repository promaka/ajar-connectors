<!-- SPDX-License-Identifier: Apache-2.0 -->
# Attributes: what connectors emit, and where the schema lives

## The ontology is authoritative — this file is not

The governed attribute set — canonical **names, units, and bounds** — is defined by
**Core's signed ontology manifest**, not by this document. A hand-maintained copy
here would drift the moment Core bumps the ontology, and the people most likely to
act on a stale copy (operators writing `generic` mappings) are exactly the ones we
must not mislead.

Dump the current, authoritative set from Core:

```sh
ajar export-ontology ontology.json
```

That manifest is the single source of truth for which keys are governed and in
what unit and bounds. Everything below is *connector behaviour*, which is stable
and independent of any particular ontology version.

## How a connector emits

A connector does not decide what is valuable:

1. **Raw frame → `Event.payload`, verbatim.** Nothing the parser does not yet map
   is lost; a future ontology can re-extract from the stored raw. (For connectors
   that correlate across frames, the payload carries every contributing frame; if a
   bounded buffer overflowed, the event is marked `payload_truncated`.)
2. **Every decoded field → an attribute.** The connector does not gate on the
   ontology. Core's ingest **demotes any undeclared key to quarantine metadata**
   (`demote_to_quarantine`) — so a field the ontology has not declared is never
   rejected and never lost, just ungoverned. A later ontology change promotes it
   with no connector change.
3. **Native identifiers** (CoT uid, MMSI, ICAO, MAVLink sysid, ASTERIX track) ride
   as metadata / `source_uid`, never the event id (always a fresh UUIDv7).
   Confidence is the event's first-class `confidence` field.

## Units are the connector's job — and the trap to avoid

Governed attributes are declared in **specific units**. A value in the wrong unit
usually still passes bounds validation and is then **silently wrong**: knots into an
m/s `speed` is off by ~1.94×; feet/minute into an m/s `vertical_rate` by ~197×; and
feet into the metres `GeoPoint` altitude is unvalidated entirely. So each connector:

- **normalises to the declared unit** (speeds → m/s, vertical rate → m/s, altitude →
  metres, …), and
- **keeps the native value in metadata** — `speed_kn`, `vertical_rate_ftmin`,
  `altitude_ft` — per ADR-0019, so nothing is lost and the conversion is auditable.

`heading` and `course` are **distinct**: `heading` is where the platform points,
`course` is its track over the ground. CoT `<track course>` and a GPS course map to
`course`; a MAVLink `hdg` maps to `heading`. Do not cross them — it misdraws the
direction tick.

## Per-connector notes

The specific keys a connector currently emits live in that connector's `src` and
README; whether a given key is *governed* is answered by the manifest above, not
restated here. In brief: `tak-cot`, `ais-nmea`, `mavlink`, `asterix`, and `adsb`
decode a standard's position and tactical fields; `generic` emits exactly what its
`[mapping]` block names — so a `generic` operator must use the manifest's canonical
names and units (e.g. `speed` in m/s, `frequency_hz` in Hz), or the value simply
rides as ungoverned metadata.
