<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-mavlink

Ingress connector for MAVLink, the telemetry protocol most UAS autopilots and
ground stations speak. It turns each vehicle's position messages into
`mim:aircraft` tracks, carrying the vehicle's latest attitude, air data, power
and GPS state, and publishes them to Core as signed events. Nothing changes on
the vehicle side: the connector reads the MAVLink the autopilot or ground
station already forwards.

## Input

MAVLink v1 (magic `0xFE`) and v2 (magic `0xFD`) frames of the common dialect,
one frame per transport frame. Autopilots and ground stations usually forward
MAVLink over UDP, so `udp` is the usual transport.

| Message | Id | Handling |
|---|---|---|
| GLOBAL_POSITION_INT | 33 | Emits an event |
| GPS_RAW_INT | 24 | Emits an event; also caches the fix quality |
| HEARTBEAT | 0 | Updates the vehicle's cached state |
| SYS_STATUS | 1 | Updates the vehicle's cached state |
| ATTITUDE | 30 | Updates the vehicle's cached state |
| VFR_HUD | 74 | Updates the vehicle's cached state |
| BATTERY_STATUS | 147 | Updates the vehicle's cached state |
| Any other id | | No event; the frame is carried to the vehicle's next event |

For the seven decoded messages the CRC (CRC-16/MCRF4XX with the message's
CRC_EXTRA) is verified before any field is read. A mismatch is rejected as
`BadCrc`: the frame is corrupt or from a dialect with a different CRC_EXTRA.
The connector has no CRC_EXTRA for other messages, so their CRC is not
checked. A v2
payload trimmed of trailing zero bytes is zero-extended to its full length.
A frame shorter than its length field claims is rejected as `Truncated`, a
first byte other than a magic as `NotMavlink`.

## Output

Every event is `mim:aircraft`. Identity: the MAVLink system id is `source_uid`
and `mav_sysid`, and the governed identity (`alt_id` = system id,
`alt_id_standard` = `MAVLink`). The location is the message's latitude,
longitude and altitude above mean sea level in metres. The timestamp is the
time of receipt, because MAVLink position messages carry a boot-relative clock.

From the position message itself:

| Attribute | Unit | From |
|---|---|---|
| `speed` | m/s | Ground speed: the horizontal velocity vector (33), or `vel` (24) |
| `heading` | degrees | True heading (33 only) |
| `course` | degrees | Course over ground (24 only) |
| `vertical_rate` | m/s, positive up | `vz` (33), else the cached VFR_HUD climb rate |
| `relative_altitude` | m | Altitude above home (33 only) |
| `position_accuracy_h_m` | m | GPS_RAW_INT `h_acc` (24 only) |
| `position_accuracy_v_m` | m | GPS_RAW_INT `v_acc` (24 only) |
| `speed_accuracy` | m/s | GPS_RAW_INT `vel_acc` (24 only) |
| `angle_accuracy` | degrees | GPS_RAW_INT `hdg_acc` (24 only); above 360 omitted |

From the vehicle's cached state, on every event once known:

| Attribute | Unit / values | From |
|---|---|---|
| `vehicle_type` | `fixed-wing`, `multirotor`, `helicopter`, `airship`, `ground-vehicle`, `surface-vessel`, `submarine`, `vtol` | HEARTBEAT `type`; other types omitted |
| `status` | `uninitialised`, `booting`, `calibrating`, `standby`, `active`, `critical`, `emergency`, `powering-off`, `terminating` | HEARTBEAT `system_status` |
| `armed` | `true` / `false` | HEARTBEAT safety-armed flag |
| `mode` | `auto`, `guided`, `stabilize`, `manual` | HEARTBEAT base-mode flags, most specific first |
| `roll`, `pitch`, `yaw` | degrees; `yaw` 0 to 360 | ATTITUDE, radians converted |
| `airspeed` | m/s | VFR_HUD |
| `throttle` | percent | VFR_HUD |
| `battery_voltage` | V | SYS_STATUS, or BATTERY_STATUS `voltages[0]` |
| `battery_current` | A | SYS_STATUS or BATTERY_STATUS |
| `battery` | percent remaining | SYS_STATUS or BATTERY_STATUS |
| `battery_consumed` | mAh | BATTERY_STATUS |
| `battery_temp` | °C | BATTERY_STATUS |
| `cpu_load` | percent | SYS_STATUS |
| `gps_fix` | `no-gps`, `no-fix`, `2d`, `3d`, `dgps`, `rtk-float`, `rtk-fixed`, `static`, `ppp` | GPS_RAW_INT |
| `gps_satellites` | count | GPS_RAW_INT |
| `gps_hdop` | dimensionless | GPS_RAW_INT `eph` / 100 |
| `hostility` | as configured | Only with `default_hostility` |

MAVLink "unknown" sentinels (all-ones, `-1`, `INT16_MAX` for temperature, `0`
for the GPS accuracy extensions) leave the attribute absent.

| Metadata | Content |
|---|---|
| `source_uid` | System id |
| `mav_sysid` | System id |
| `custom_mode` | Autopilot-specific mode number, when the HEARTBEAT custom-mode flag is set. ArduPilot and PX4 number modes differently |
| `payload_truncated` | `true` when carried frames were dropped over the cap |

Payload: every frame received from the system id since its last event,
concatenated, ending with the position frame. Frames self-delimit by their
length field, so the payload can be walked frame by frame.

## Configuration

Copy [`mavlink.example.toml`](mavlink.example.toml). The connector-specific
setting is `default_hostility` (default none): the `hostility` attribute on
every event. MAVLink carries none, so without it none is emitted.

```toml
[transport]
kind = "udp"
bind = "0.0.0.0:14550"
```

```bash
ajar-mavlink ./mavlink.toml
ajar-mavlink ./mavlink.toml --profile   # print the profile to register, then exit
```

## Behaviour

### Per-vehicle state

HEARTBEAT, SYS_STATUS, ATTITUDE, VFR_HUD, BATTERY_STATUS
and the fix quality of GPS_RAW_INT update a snapshot kept per system id. Every
later position event of that vehicle carries the latest value of each field.
A field stays absent until a message reports it. When both SYS_STATUS and
BATTERY_STATUS are sent, whichever arrived last sets the shared battery fields.

### GPS accuracy

The GPS_RAW_INT accuracy extensions ride only on a
GPS_RAW_INT event. A GLOBAL_POSITION_INT is the autopilot's filtered estimate,
so the receiver's uncertainty does not apply to it. A MAVLink 1 sized
GPS_RAW_INT states no accuracy.

### One track per system id

Vehicles sharing a stream need distinct
`SYSID_THISMAV`. ArduPilot and PX4 both default to 1, and two vehicles with the
same id merge into one track with their frames mixed in the payload. The
connector logs the first frame from each new system id, so the count can be
checked against the number of airframes. The component id is not used.

### Carry-forward

Frames that do not emit an event are held per system id and
sealed into that vehicle's next event. The buffer holds at most 128 frames or
32 KiB per vehicle. Past that the oldest frame is dropped, the next event gets
`payload_truncated = true`, and `connector_dropped_carryforward_total` counts
the drop. A frame that fails its CRC is not carried.

## Limits

- Only the seven messages above are decoded, from the common dialect.
- One frame per transport frame.
- MAVLink 2 signatures are not verified.

## Conformance

`cargo test` checks that events meet Core's content contract (UUIDv7 id,
RFC 3339 timestamp, sorted metadata) and that the seal verifies under the
published contract key. The decode is checked against CRC-correct MAVLink 1
GLOBAL_POSITION_INT and HEARTBEAT frames, the HEARTBEAT pinned byte for byte
with the synthetic feed. Property tests run 4096 cases each of arbitrary bytes
and length-lying framed input and assert the parser never panics.
