<!-- SPDX-License-Identifier: Apache-2.0 -->
# Tactical attribute reference

Every connector extracts the tactical attributes an operating picture needs and
routes each one **per key**: a key listed in the connector config's
`governed_attributes` rides as a **governed attribute** (type-validated and
correlated by Core); every other key rides as **metadata** (always accepted,
surfaced to the C2, not validated). One undeclared key can therefore never cost a
whole track — the safe default (`governed_attributes = []`) routes everything to
metadata and works against any deployment.

Native identifiers (CoT uid, MMSI, IMO, MAVLink system id, ASTERIX track/ICAO)
are **always metadata**, never governed and never the event id (the id is a fresh
UUIDv7). Confidence is the event's first-class `confidence` field and needs no
declaration.

## The standard set, per connector

This is the exact list to declare in the deployment's ontology (Core ships the
same set pre-declared in its ontology seed). Once declared, put the keys in
`governed_attributes` in the connector's config:

| Connector | Entity type(s) | Governed-attribute keys |
|-----------|----------------|-------------------------|
| tak-cot | `mim:aircraft`, `mim:vessel`, `x:cot:*` | `affiliation`, `callsign` |
| ais-nmea | `mim:vessel` | `affiliation`, `speed`, `course`, `heading`, `rate_of_turn`, `nav_status`, `vessel_type`, `vessel_name`, `callsign` |
| mavlink | `mim:aircraft` | `affiliation`, `speed`, `heading`, `course`, `vertical_speed`, `relative_altitude`, `vehicle_type`, `status`, `armed`, `mode`, `roll`, `pitch`, `yaw`, `airspeed`, `throttle`, `battery_voltage`, `battery_current`, `battery_remaining`, `battery_consumed`, `battery_temp`, `cpu_load`, `gps_fix`, `gps_satellites`, `gps_hdop` |
| asterix | `mim:aircraft` | `affiliation`, `speed`, `course`, `squawk`, `callsign`, `aircraft_type` |
| generic | per mapping | `affiliation`, plus whatever the operator maps in `[mapping.attributes]` |

## Key semantics and units

| Key | Meaning | Values / unit |
|-----|---------|---------------|
| `affiliation` | force identity | `friendly` \| `hostile` \| `neutral` \| `unknown` (CoT derives it from the type; the other feeds carry none, so set `default_affiliation` in config) |
| `callsign` | callsign / flight identity | free text as broadcast |
| `speed` | speed over ground | knots, 1 decimal |
| `course` | course over ground / track angle | degrees, 1 decimal |
| `heading` | true heading | degrees |
| `rate_of_turn` | rate of turn (AIS class A) | degrees/minute |
| `nav_status` | AIS navigation status | `under-way-using-engine`, `at-anchor`, `engaged-in-fishing`, … |
| `vessel_type` | AIS ship-type category | `cargo`, `tanker`, `fishing`, `military-ops`, … |
| `vessel_name` | vessel name from AIS static data | free text |
| `vehicle_type` | MAVLink vehicle category | `fixed-wing`, `multirotor`, `helicopter`, `vtol`, … |
| `status` | MAVLink system status | `active`, `standby`, `critical`, `emergency`, … |
| `armed` | MAVLink armed state | `true` \| `false` |
| `mode` | MAVLink coarse flight mode | `auto`, `guided`, `stabilize`, `manual` (autopilot-specific detail rides `custom_mode` metadata) |
| `vertical_speed` | climb rate, positive up | m/s, 1 decimal |
| `relative_altitude` | altitude above home | metres, 1 decimal |
| `roll` / `pitch` / `yaw` | attitude (ATTITUDE msg) | degrees, 1 decimal (`yaw` normalised 0–360) |
| `airspeed` | indicated airspeed (VFR_HUD) | knots, 1 decimal |
| `throttle` | throttle setting (VFR_HUD) | percent |
| `battery_voltage` / `battery_current` | pack voltage / current | volts (2 dp) / amps (2 dp) |
| `battery_remaining` | charge remaining | percent |
| `battery_consumed` | charge consumed | mAh |
| `battery_temp` | battery temperature | degrees C, 1 decimal |
| `cpu_load` | autopilot CPU load | percent |
| `gps_fix` | GPS fix quality | `no-fix`, `2d`, `3d`, `dgps`, `rtk-float`, `rtk-fixed`, … |
| `gps_satellites` | satellites visible | count |
| `gps_hdop` | horizontal dilution of precision | unitless, 2 decimals |
| `squawk` | Mode 3/A code | four octal digits (e.g. `7700`) |
| `aircraft_type` | ADS-B emitter category | `light`, `heavy`, `rotorcraft`, `uav`, … |

## Config example

```toml
# Declared in this deployment's ontology -> ride governed; the rest -> metadata.
governed_attributes = ["affiliation", "callsign", "speed", "course"]
# Feeds that carry no affiliation get this one (e.g. own-force UAS).
default_affiliation = "friendly"
```
