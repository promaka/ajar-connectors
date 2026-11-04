<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-klv: STANAG 4609 / MISB ST 0601 (KLV) ingress

Ingress for the MISB ST 0601 **UAS Datalink Local Set**, the KLV
(Key-Length-Value, SMPTE 336M) metadata that full-motion-imagery platforms
such as UAS, ISR pods and gimbals emit under STANAG 4609. Each set with a
sensor position becomes one signed canonical Ajar event. It is the worked
example of a tag-length-value binary format (see
[`AGENTS.md`](../../../AGENTS.md)).

## Input

One UAS Local Set per frame: the 16-byte ST 0601 Universal Label, a BER
length, then BER-OID tagged items. The last two bytes of the set are the
ST 0601 16-bit checksum (tag 1), computed over every byte before them. Bytes
after the set's declared length are ignored.

Decoded tags:

| Tag | Field |
|----:|-------|
| 2 | Precision Time Stamp |
| 3 | Mission ID |
| 4 | Platform Tail Number |
| 5 | Platform Heading Angle |
| 6 | Platform Pitch Angle |
| 7 | Platform Roll Angle |
| 10 | Platform Designation |
| 13, 14 | Sensor Latitude, Longitude |
| 15 | Sensor True Altitude |
| 65 | UAS LS Version Number |

Every other tag is skipped and stays in the payload.

Transports: `udp` with one set per datagram, as in the example config, or a
stream transport such as `tcp-server` with `framing = "length-delimited"`.

The input is extracted KLV, not an MPEG-TS stream. See
[CONNECTORS.md](../../../CONNECTORS.md#ajar-klv-stanag-4609--misb-st-0601) for
how to extract it.

## Output

Entity type `mim:aircraft`, one event per set that carries both sensor
latitude and longitude.

**Identity.** `source_uid` is the tail number (tag 4), else the platform
designation (tag 10), so each platform is its own track. A set with neither
has no `source_uid`.

**Location.** Sensor latitude and longitude (tags 13, 14) in degrees, and
sensor true altitude (tag 15) in metres.

**Time.** The Precision Time Stamp (microseconds since the Unix epoch), else
receipt time.

| Attribute | Unit | Source |
|---|---|---|
| `heading` | degrees, one decimal, 0 to 360 | tag 5 |
| `pitch` | degrees, one decimal, -20 to 20 | tag 6 |
| `roll` | degrees, one decimal, -50 to 50 | tag 7 |
| `platform_designation` | text | tag 10 |
| `hostility` | MIM `HostilityCodeType` | `default_hostility`, only when configured |

In the vendored ontology, `heading` is governed on `mim:aircraft`, and `pitch`,
`roll` and `platform_designation` are not. See
[ATTRIBUTES.md](../ATTRIBUTES.md) for what a graceful or a strict site does with
an undeclared key.

| Metadata | Content |
|---|---|
| `source_uid` | as above |
| `tail_number` | tag 4 |
| `mission_id` | tag 3 |
| `uas_ls_version` | tag 65 |

Text tags are trimmed; an empty one is absent.

**Payload.** The whole Local Set, from the Universal Label to the checksum,
verbatim.

## Configuration

Start from [`klv.example.toml`](klv.example.toml). The connector has no
`[options]`. `default_hostility` sets the `hostility` attribute; KLV carries
none of its own, and with it unset none is emitted.

## Behaviour

- Sets are independent; nothing is correlated across frames.
- The ST 0601 error indicators (`i32::MIN` for latitude and longitude,
  `i16::MIN` for pitch and roll) decode as absent. A value of the wrong length
  for its tag is also absent.
- The frame is rejected when the Universal Label is wrong, a BER length is in
  indefinite form or wider than 4 bytes, a length runs past the set, or the
  checksum does not match.

## Limits

- Of the roughly 100 ST 0601 tags, only those above are decoded. Platform
  speeds, sensor pointing, frame centre and target data are payload only.
- Only the ST 0601 UAS Local Set is accepted. Other MISB local sets, and
  several sets in one frame, are not decoded.

## Run

```sh
cp klv.example.toml klv.toml   # edit source_id, key path and [transport]
ajar-klv ./klv.toml
ajar-klv --profile ./klv.toml  # print the profile the operator registers
```
