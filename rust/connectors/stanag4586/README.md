<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-stanag4586: STANAG 4586 (NATO UAS Control) ingress

Ingress for the telemetry on the STANAG 4586 **Data Link Interface (DLI)**,
the messages a vehicle-specific module (VSM) sends to the Core UAS Control
System (CUCS). Vehicle-state reports become signed canonical Ajar tracks. The
connector only reads; it does not command or control vehicles. It covers the
larger tactical and MALE platforms and ground stations that speak 4586;
[`mavlink`](../mavlink) covers small and commercial-derived UAS.

## Input

STANAG 4586 Edition 2 DLI messages, laid out from the NATO UNCLASSIFIED
Edition 2 field tables. Each message is a 30-byte wrapper, the body and a
4-byte checksum, big-endian throughout with IEEE 754 floats (§B.3.3.1):

```text
IDD version    10 bytes  null-terminated ASCII
instance id     u32
message type    u32      1..<2000 standard, >2000 vehicle-specific
message length  u32      body bytes
stream id       u32
packet seq      u32      unused, -1
<body>
checksum        u32      byte-wise unsigned sum of all preceding bytes
```

One frame may pack several messages back to back; each has its own checksum.

- **Message #101 Inertial States** (§B.4.1.2.11, Table B1-25): decoded.
- **Every other message type**: checksum-validated and skipped.

The wrapper's IDD version, instance id, stream id and packet sequence are not
read.

Big-endian follows the published field tables. An open reference
implementation packs its structs in native little-endian order; that order is
not followed. The reference was consulted only to confirm the wrapper length,
and no code was copied from it.

Transport: `udp` on the VSM's DLI output, as in the example config, or
`udp-multicast` if the VSM multicasts.

## Output

Entity type `mim:aircraft` by default, one event per #101 message.

**Identity.** `source_uid` is `s4586:vehicle:<vehicle id>`, so each vehicle is
its own track.

**Location.** Latitude and longitude, radians on the wire, in degrees. The
altitude is the #101 altitude in metres as sent, whatever its reference; the
`altitude_type` metadata says which reference that is.

**Time.** The #101 Time Stamp (UTC seconds since 1970, §B.1.7). A value that
is not finite or out of range falls back to receipt time.

| Attribute | Unit | Source |
|---|---|---|
| `speed` | m/s, two decimals | horizontal magnitude of the north and east velocity |
| `course` | degrees true, one decimal, 0 to 360 | direction of the north and east velocity |
| `heading` | degrees, one decimal, 0 to 360 | yaw (Psi) |
| `vertical_rate` | m/s, two decimals, climb positive | the down velocity, negated |
| `hostility` | MIM `HostilityCodeType` | `default_hostility`, only when configured |

`heading` is where the airframe points, `course` is its track over the
ground; they are not interchangeable.

| Metadata | Content |
|---|---|
| `source_uid` | as above |
| `cucs_id` | the CUCS id from the message |
| `altitude_type` | `pressure`, `baro`, `agl`, `wgs84` or `unknown` |
| `roll_deg`, `pitch_deg` | attitude, degrees, two decimals |
| `magnetic_variation_deg` | degrees, three decimals |
| `timestamp_s` | the native Time Stamp, seconds, three decimals |

**Payload.** The whole message, wrapper and checksum included, verbatim. A
frame with two #101 messages yields two events, each carrying its own message.

## Configuration

Start from [`stanag4586.example.toml`](stanag4586.example.toml). The
connector has no `[options]`.

- `default_hostility` sets the `hostility` attribute. 4586 carries none, and
  with it unset none is emitted.
- `[entity_map] default = "<type>"` replaces the entity type, default
  `mim:aircraft`. MIM 5.3 has no uncrewed class, so a UAS is an aircraft.

## Behaviour

- Messages are independent; nothing is correlated across frames.
- A checksum mismatch on any message rejects the whole frame, including
  messages before it that decoded.
- A #101 body shorter than 89 bytes rejects the whole frame.
- Trailing bytes too short for a wrapper and checksum are ignored.
- A frame holding only other message types yields no events and no error.

## Limits

- Only #101 Inertial States is decoded. Other DLI messages, such as #20
  Vehicle ID, are not mapped.
- The #101 accelerations and attitude rates are not decoded; they stay in the
  payload.
- Altitude is not converted between references, so a pressure or AGL altitude
  becomes the event altitude unchanged.

## Run

```sh
cp stanag4586.example.toml stanag4586.toml   # edit source_id, key path, [transport]
ajar-stanag4586 ./stanag4586.toml
ajar-stanag4586 --profile ./stanag4586.toml  # print the profile the operator registers
```

## Conformance

`cargo test -p ajar-stanag4586` decodes a hand-built #101 message and checks
position, derived kinematics, heading against course, the timestamp and
identity. It checks the event against Core's content contract and the seal
against the published contract key. It confirms that two messages in one
frame yield two events, that corrupt checksums, lying lengths and short bodies
are handled without a panic, and fuzzes the walk with arbitrary and
wrapper-shaped input.
