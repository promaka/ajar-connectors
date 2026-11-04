<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-gmti: STANAG 4607 (NATO GMTI) ingress

Ingress for **GMTI** (Ground Moving Target Indicator) radar packets in the
STANAG 4607 format. Each located target report in a Dwell segment becomes one
signed canonical Ajar event. It is the worked example of an existence-mask
binary format (see [`AGENTS.md`](../../../AGENTS.md)).

## Input

One STANAG 4607 packet per frame: a 32-byte packet header, then a run of
segments. The header's edition byte must be 2 or 3, and its declared packet
size must be at least 32 bytes and fit in the frame. Bytes after the declared
packet size are ignored.

- **Packet header**: platform id (bytes 14 to 23, trimmed) and job id are read.
- **Dwell segment** (type 2): decoded. Its 8-byte **existence mask** says which
  optional dwell and target fields are present. The connector reads the
  dwell index, dwell time, sensor position, the lat/lon scale factors, the
  dwell area centre and each target report. Other optional fields are skipped
  by size so the reports stay aligned.
- **Other segments** (Mission, Job Definition, HRR and the rest): skipped by
  their declared size.

Field order, sizes, mask bits and scale factors follow STANAG 4607,
cross-checked against the Wireshark dissector and the pentlandedge `s4607`
implementation.

Transports: `udp` with one packet per datagram, as in the example config, or a
stream transport such as `tcp-server` with `framing = "length-delimited"`.

## Output

Entity type `mim:object`, one event per located target report.

**Identity.** GMTI target reports are untracked detections; the format has no
persistent target id. `source_uid` is
`<platform>:<job_id>:<dwell_index>:<mti_report_index>`, unique per detection,
with `na` in place of the report index when the report has none. It does not
persist for the same vehicle across dwells; downstream fusion associates
detections.

**Location.** The report's high-resolution lat/lon if present, else the
dwell area centre plus the delta lat/lon times the dwell's scale factors.
Longitudes are normalised to -180..180. Altitude is the target height in
metres.

**Time.** Dwell time is relative to the Mission Segment reference time, which
may be in another packet, so the event is stamped with receipt time.

| Attribute | Unit | Source |
|---|---|---|
| `radial_velocity` | m/s, two decimals | D32.7 line-of-sight velocity, native cm/s. Not ground `speed`. |
| `snr_db` | dB | D32.9 |
| `classification_code` | STANAG 4607 code | D32.10 |
| `rcs_db` | raw signed byte | D32.18, see Limits |
| `hostility` | MIM `HostilityCodeType` | `default_hostility`, only when configured |

An attribute is emitted only when its mask bit is set.

| Metadata | Content |
|---|---|
| `source_uid` | as above |
| `platform` | packet header platform id |
| `job_id` | packet header job id |
| `dwell_index` | dwell index within the revisit |
| `mti_report_index` | report index, when present |
| `dwell_time_ms` | native dwell time, ms after the mission reference |
| `sensor_lat`, `sensor_lon` | sensor position at the dwell, degrees, 6 decimals |

**Payload.** The whole Dwell segment, including its 5-byte segment header,
verbatim. Every target event from that dwell carries the same segment.

## Configuration

Start from [`gmti.example.toml`](gmti.example.toml). The connector has no
`[options]`. `default_hostility` sets the `hostility` attribute; GMTI carries
none of its own, and with it unset none is emitted.

## Behaviour

- Packets are independent; nothing is correlated across frames.
- A packet with no Dwell segment yields no events.
- The frame is rejected as a whole when the edition is not 2 or 3, the
  declared packet size does not fit, a segment declares a size below 5 bytes
  or past the packet end, or a dwell runs past its segment.

## Limits

- Only Dwell segments are decoded. The Mission Segment reference time is not
  used, so events carry receipt time rather than dwell time.
- Sensor altitude, sensor kinematics, orientation, dwell extents, wrap
  velocity and the report uncertainty and truth-tag fields are skipped.
- The delta lat/lon scaling and the RCS unit (dB or half dB) are not yet
  checked against a real radar capture. `rcs_db` carries the byte unscaled.
  Validate against your radar's output before production.

## Run

```sh
cp gmti.example.toml gmti.toml   # edit source_id, key path, [transport]
ajar-gmti ./gmti.toml
ajar-gmti --profile ./gmti.toml  # print the profile the operator registers
```
