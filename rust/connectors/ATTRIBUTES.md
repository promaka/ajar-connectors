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

## A domain is not a classification

`entity_type` says what a thing *is*. Many feeds only report which environment it
is in, which is a different and weaker statement: STANAG 4676's `LAND` means
"somewhere on the ground", not "a vehicle". Mapping that to a specific type would
assert something the source never said, and a fabricated classification reaches an
operator looking exactly as authoritative as a real one.

So: **when a source reports a domain rather than a classification, emit
`mim:object`.** Use a specific type only when the source actually identified the
thing. `mim:object` says "something is here, unclassified", which is true, and the
domain still rides as an attribute so nothing is lost.

This is why GMTI emits `mim:object` — it produces moving-target detections with no
classification at all — and why a `LAND` track from STANAG 4676 does too.

Note also that MIM 5.3 has no uncrewed-aircraft class. A UAS is `mim:aircraft`:
the airframe is the thing, and crewing is a property of it.

### `environment` is an Ajar extension, not MIM

`environment` is a closed set that Core governs, and it drives the CoT battle
dimension:

| `environment` | CoT dimension |
|---|---|
| `AIR` | `A` |
| `LAND` | `G` |
| `SURFACE` | `S` |
| `SUBSURFACE` | `U` |
| `SPACE` | `P` |
| `UNKNOWN`, or anything else | `X` |

No function suffix is emitted with it, because a suffix draws a specific platform
symbol and that is the assertion nobody made. So an air contact of unknown type
renders as `a-u-A`, in the air dimension and unidentified, rather than a bare
`a-u-X`. Being honest about what the source did not say costs nothing on the map.

**It is an Ajar extension.** MIM 5.3 has no domain concept at all —
`EnvironmentalActionCategoryCode` and `EstablishmentEnvironmentConditionCode` are
unrelated things. It was declared deliberately and is marked as an extension in
the seed. Do not assume it is MIP vocabulary, and do not expect a MIM class to
correspond to it.

The values are exact case and the set is closed, so a connector must normalise
rather than pass a wire value through. STANAG 4676 is the live example: STANAG
1241 spells it `SUB-SURFACE` with a hyphen, and its enums are extensible, so both
the hyphen and any unrecognised token are mapped before emission. A connector that
forwarded the wire value would have its tracks quarantined and lose their battle
dimension without anything appearing to fail.

## `hostility` is a controlled vocabulary, and the case is exact

`hostility` carries MIM 5.3 `HostilityCodeType`, and only these values:

```
Friend  AssumedFriend  Hostile  AssumedHostile  Suspect
Neutral  AssumedNeutral  Involved  AssumedInvolved
Pending  Unknown  Faker  Joker
```

Not `friendly`, not `FRIEND`. This is the attribute where a mistake is hardest to
notice: Core runs graceful mode by default, so an unrecognised name or value is
not rejected. The event is accepted, the field is dropped, and the deployment
looks healthy while the map loses its friend-or-foe colouring. After changing
anything here, check `ajar_attributes_quarantined_total{attribute="hostility"}`
reads zero. That metric holds at most 32 distinct attribute names and overflows
the rest into `other`, so if the `hostility` series is absent rather than zero,
check `other` before concluding it is clean.

`Faker` and `Joker` are exercise codes, a friendly simulating hostile and a track
playing suspect. A connector with an exercise mode should emit those rather than
`Hostile`, so a trial never reaches an operator as a real threat.

Note this is *not* MIM's `affiliation`, which means nationality and ethnicity.

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
