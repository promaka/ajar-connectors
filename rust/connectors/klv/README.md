<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-klv — STANAG 4609 / MISB ST 0601 (KLV) connector

Ingests the **UAS Datalink Local Set** that full-motion-imagery platforms (UAS,
ISR pods, gimbals) emit as **KLV** (Key-Length-Value, SMPTE 336M) metadata, and
turns each set into a signed canonical Ajar event.

This is also the repo's **reference binary-STANAG connector** — the worked
example an operator or an agent follows to add a connector for any bit/byte
format (see the top-level [`AGENTS.md`](../../../AGENTS.md)).

## What it decodes

The common ST 0601 platform tags:

| Tag | Field | Canonical mapping |
|----:|-------|-------------------|
| 2 | Precision Time Stamp | event `timestamp` |
| 4 | Platform Tail Number | `source_uid` + `tail_number` metadata |
| 5 | Platform Heading | `heading` attribute (deg) |
| 6 / 7 | Platform Pitch / Roll | `pitch` / `roll` attributes (deg) |
| 10 | Platform Designation | `platform_designation` attribute |
| 13 / 14 | Sensor Latitude / Longitude | event location |
| 15 | Sensor True Altitude | event location altitude (m) |
| 65 | UAS LS version | `uas_ls_version` metadata |
| 1 | Checksum | validated (fail-closed on mismatch) |

## What it does *not* decode — and why that's safe

ST 0601 defines ~100 tags. This connector maps the platform subset above; **every
other tag is preserved verbatim in `Event.payload`** (the whole raw KLV set is
sealed into the signed event). Nothing is dropped at the connector: a later
ontology, or a generated extension of this parser, can re-extract any tag from
the stored raw. This is the connector-suite's core rule — *a connector must not
decide what is valuable.*

## Units

`heading`/`pitch`/`roll` are degrees; altitude is metres (per ST 0601 scaling).
Angles use the ST 0601 signed-integer mapping, and the `i32::MIN`/`i16::MIN`
"error" indicators decode to *absent*, never a fabricated value.

## Run it

```sh
cp klv.example.toml klv.toml   # edit source_id, key path, and [transport]
ajar-klv ./klv.toml
```

Each platform is its own track (tail number → stable `source_uid`), so Core never
collapses multiple airframes onto the connector `source_id`.
