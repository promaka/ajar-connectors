<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-ais-nmea

Ingress connector for a ship's or coast station's NMEA 0183 feed. It decodes
AIS transponder reports into `mim:vessel` tracks and ARPA radar tracked targets
(`TTM`) into `mim:object` contacts, and publishes both to Core as signed events.
One feed and one config give both the transponder picture and what the radar
sees. Nothing changes on the AIS side: the connector reads the sentences the
receiver already emits.

## Input

NMEA 0183 sentences, one per frame, each with a valid `*HH` checksum (XOR of
every byte between the `!`/`$` and the `*`). An NMEA 4.0 TAG block
(`\s:...,c:...*hh\`) before a sentence is skipped for parsing; only the
sentence's own checksum is verified.

| Sentence | Handling |
|---|---|
| `!--VDM`, `!--VDO` types 1, 2, 3 (class A), 18, 19 (class B) | Position report, one event. Type 19 also updates the identity cache |
| `!--VDM`, `!--VDO` types 5, 24 | Name, call sign, ship type and IMO cached per MMSI; no event |
| `!--VDM`, `!--VDO` other types | No event; the sentence is carried to the MMSI's next position (see Behaviour) |
| `$--TTM` | Radar target, one event when its status is `T` (tracking) |
| `$--GGA`, `$--RMC` | Own-ship fix for placing TTM targets; no event |
| Any other NMEA sentence (`HDT`, `DPT`, `MWV`, ...) | Ignored, not an error |

Multi-part AIS messages are reassembled. AIS bit offsets match the pyais
reference decoder. A frame that is not UTF-8, does not start with `!` or `$`,
fails its checksum, or is a VDM/VDO or TTM with too few fields is rejected
with a typed error and counted. A GGA or RMC without a valid fix is ignored.

Transports that fit: `serial` (bridge RS-232/RS-422 wiring), `tcp-client` to an
aggregator or ship-network NMEA server, `udp` from a receiver that sends one
sentence per datagram. Stream transports use the default `line` framing.

## Output

### AIS: `mim:vessel`

Identity: `source_uid` is the MMSI. When the MMSI is 1 to 999999999 it is also
the governed identity, `alt_id` = the MMSI as nine digits with leading zeros,
`alt_id_standard` = `AIS`. MMSI 0 (an unconfigured transponder) and larger
values get no governed identity.

The location is the reported latitude and longitude at altitude 0. A report
with "not available" or out-of-range coordinates has no location. The
timestamp is the time of receipt, because AIS position reports carry no
absolute time.

| Attribute | Unit / values | From |
|---|---|---|
| `speed` | m/s | Speed over ground, knots converted; 102.3 (not available) omitted |
| `course` | degrees | Course over ground; 360 (not available) omitted |
| `heading` | degrees | True heading; 511 (not available) omitted |
| `rate_of_turn` | degrees per minute, positive to starboard | Class A only; -128 (not available) omitted |
| `nav_status` | `under-way-using-engine`, `at-anchor`, `not-under-command`, `restricted-manoeuvrability`, `constrained-by-draught`, `moored`, `aground`, `engaged-in-fishing`, `under-way-sailing`, `reserved`, `ais-sart` | Class A only |
| `vessel_type` | e.g. `fishing`, `tug`, `passenger`, `cargo`, `tanker`, `military-ops`, `law-enforcement` | Cached ship-type code; codes without a category omitted |
| `vessel_name` | text | Cached static data |
| `callsign` | text | Cached static data |
| `alt_id`, `alt_id_standard` | see Identity | |
| `hostility` | as configured | Only with `default_hostility` |

| Metadata | Content |
|---|---|
| `source_uid` | MMSI |
| `mmsi` | MMSI, also when it is 0 |
| `speed_kn` | Native speed over ground in knots |
| `imo` | IMO number from type 5, when known |
| `payload_truncated` | `true` when carried sentences were dropped over the cap |

Payload: every raw sentence received for the MMSI since its last event,
newline-joined, ending with the position report's own sentence or fragments.
Each sentence is kept as it arrived, TAG block included.

### Radar targets: `mim:object`

Every tracked target is `mim:object` with `environment = SURFACE`. A radar
return says something is on the surface, not what it is. `source_uid` is
`arpa-<target number>`. The timestamp is the time of receipt. The location is
set only as described under Behaviour.

| Attribute | Unit | From |
|---|---|---|
| `environment` | `SURFACE` | Always |
| `speed` | m/s | Target speed, converted from the sentence's units |
| `course` | degrees | Target course, only when flagged true (`T`) |
| `callsign` | text | The label the radar operator gave the target |
| `hostility` | as configured | Only with `default_hostility` |

| Metadata | Content |
|---|---|
| `source_uid` | `arpa-<number>` |
| `target_number` | Target number as the radar reports it |
| `range_m` | Range from the observer in metres |
| `bearing_deg` | Bearing in degrees, true or relative as the sentence flags it |
| `cpa_m` | Closest point of approach in metres |
| `tcpa_min` | Time to closest point of approach in minutes |

TTM distance and speed are converted by the sentence's units field: `N`
(nautical miles and knots, also the default), `K` (km and km/h), `S` (statute
miles and mph). Payload: the TTM sentence.

## Configuration

Copy [`ais-nmea.example.toml`](ais-nmea.example.toml). Connector-specific
settings:

| Key | Default | Effect |
|---|---|---|
| `default_hostility` | none | `hostility` attribute on every event. AIS and TTM carry none, so without it none is emitted |
| `[sensor]` `lat`, `lon` | none | Fixed observer site for a shore-mounted radar's TTM targets |

On a ship, the bridge wiring is a serial port:

```toml
[transport]
kind = "serial"
device = "/dev/ttyUSB0"
baud = 38400            # the default; classic NMEA instruments run at 4800
```

If the port opens with Permission denied, add the service user to the port's
group (usually `dialout`). `ajar-doctor` checks the device.

```bash
ajar-ais-nmea ./ais-nmea.toml
ajar-ais-nmea ./ais-nmea.toml --profile   # print the profile to register, then exit
```

## Behaviour

### Static data

Types 5, 24 and the static part of 19 update a per-MMSI
identity cache. Each later position report for that MMSI carries the latest
known name, call sign, ship type and IMO. A field that arrives empty never
overwrites a known value. Type 24 part A carries the name, part B the ship type
and call sign.

### Carry-forward

A static or unmapped sentence produces no event. Its raw
bytes are held per MMSI and sealed into the payload of that vessel's next
position event, then cleared. The buffer holds at most 64 sentences or 16 KiB
per MMSI. Past that the oldest sentence is dropped, the next event gets
`payload_truncated = true`, and `connector_dropped_carryforward_total` counts
the drop.

### Bounded caches

The identity cache and the carry-forward buffers each hold
at most 10,000 MMSIs, because MMSIs come from the feed and can be spoofed. At
the cap the vessel inserted first is evicted. A live vessel's next static
message caches it again.

### Reassembly

Fragments are keyed on the talker, the radio channel and the
sequential message id, so another receiver's or channel's fragments cannot
splice into a message. Two vessels on one receiver and channel that pick the
same id within the window can still collide, since fragments carry no vessel
id. A partial message older than 10 seconds is discarded. A fragment that
arrives out of order or without its first part is discarded.

### Placing radar targets

A TTM position is a range and bearing from the
observer. The observer is the latest valid `GGA` (fix quality not 0) or `RMC`
(status `A`) on the feed, if it is at most 60 seconds old. A minute-old fix on
a ship at 20 knots is about 600 m off. Otherwise the observer is the `[sensor]`
site. A GGA/RMC fix on the feed takes precedence over the site. The target is
placed with a spherical forward solution, which is within centimetres of the
ellipsoid at radar ranges.

A target gets no location when there is no observer, or when its bearing is
relative (`R`). Resolving a relative bearing needs own heading, which TTM does
not carry, and a wrong assumption would put the contact on the wrong side of
the ship. The range and bearing still ride in metadata.

### Non-tracking targets

A TTM with status `L` (lost, a stale last report) or
`Q` (acquiring, not yet a track) produces no event. Each is counted in
`ttm_non_tracking_total`.

## Limits

- AIS message types other than 1, 2, 3, 5, 18, 19 and 24 are not decoded
  (base stations, aids to navigation, safety messages, binary messages). Their
  sentences only reach a payload if the same MMSI later sends a position.
- A UDP datagram must hold exactly one sentence.

## Try it against live traffic

The Norwegian Coastal Administration publishes its AIS network as open data,
as a raw NMEA stream:

```toml
[transport]
kind = "tcp-client"
connect = "153.44.253.27:5631"
framing = "line"
```

Vessels arrive within seconds. Run the development sink beside it to see them
sealed and verified. The sentences carry NMEA 4.0 TAG blocks, which stay in the
AIS payload.

## Conformance

`cargo test` checks that events meet Core's content contract (UUIDv7 id,
RFC 3339 timestamp, sorted metadata) and that the seal verifies under the
published contract key. The decode is checked against real, pyais-verified
`!AIVDM` sentences (MMSI 227006760 and 603916439) and a captured TAG-block
sentence from the Norwegian feed. Property tests run 4096 cases each of
arbitrary bytes and AIVDM-, TTM- and GGA/RMC-shaped input and assert the parser
never panics. A pcap replay test checks the capture is replayed with its
original pacing.
