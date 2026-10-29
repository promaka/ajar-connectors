<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-adsb

Ingress connector for **ADS-B** aircraft reports in the **SBS-1 / BaseStation**
format. It reads the line-delimited CSV that `dump1090`, `readsb` and compatible
receivers serve on TCP port 30003, and publishes one signed `mim:aircraft` event
per position report.

## Input

One SBS-1 line is one frame: 22 comma-separated fields, numbered from 0 below.
Use a stream transport with `framing = "line"`: `tcp-client` to the receiver's
port 30003, or `tcp-server` when the receiver pushes to you.

| Record | Handling |
|---|---|
| `MSG` | Decoded. Every populated field below is cached for the aircraft, whatever the transmission type. |
| `SEL`, `ID`, `AIR`, `STA`, `CLK` | Valid, carry no track. Ignored. |
| anything else | Refused as `NotSbs`. |

| Field | Content |
|---|---|
| 1 | Transmission type. 2 (surface) and 3 (airborne) are position reports. |
| 4 | ICAO 24-bit address, hex. Required on `MSG`, else `NoIcao`. |
| 10 | Callsign (MSG,1) |
| 11 | Barometric altitude, ft |
| 12, 13 | Ground speed (kt), track angle (deg) (MSG,2, MSG,4) |
| 14, 15 | Latitude, longitude (MSG,2, MSG,3) |
| 16 | Vertical rate, ft/min (MSG,4) |
| 17 | Squawk (MSG,6) |
| 21 | On-ground flag: 1 is on ground, -1 or 0 airborne |

Fields 6 to 9 (receiver timestamps) and 18 to 20 (alert, emergency, SPI) are
not decoded. They stay in the payload. Raw 1090ES or Beast input with CPR
position decoding is not supported.

## Output

Entity type `mim:aircraft`.

Identity: the ICAO address, uppercase hex, is `source_uid`, so Core keeps one
track per airframe. It is also the governed identity: `alt_id` is the address,
`alt_id_standard` is `ICAO24`.

| Attribute | Unit | Source |
|---|---|---|
| `callsign` | | field 10, trimmed |
| `speed` | m/s | field 12 |
| `course` | deg | field 13, track over ground |
| `vertical_rate` | m/s | field 16 |
| `squawk` | four octal digits | field 17 |
| `on_ground` | `true` / `false` | field 21 |
| `hostility` | | `default_hostility`, only when configured |
| `alt_id`, `alt_id_standard` | | ICAO address, `ICAO24` |

Location is the reported latitude and longitude, with the barometric altitude
in metres. Units follow [`../ATTRIBUTES.md`](../ATTRIBUTES.md).

| Metadata | Content |
|---|---|
| `source_uid`, `icao` | ICAO address |
| `speed_kn` | native ground speed |
| `vertical_rate_ftmin` | native vertical rate |
| `altitude_ft` | native altitude |
| `payload_truncated` | `true` when carried lines were dropped, see Behaviour |

The payload is every `MSG` line received for the aircraft since its last event,
ending with the position line, joined by `\n`.

## Configuration

Copy [`adsb.example.toml`](adsb.example.toml). There is no connector-specific
option. `default_hostility` sets `hostility` on every event; ADS-B carries none,
so without it no hostility is emitted. The value is case-sensitive, e.g.
`"Neutral"`.

```sh
ajar-adsb ./adsb.toml
ajar-adsb ./adsb.toml --profile   # print the profile to register, then exit
```

## Behaviour

- SBS-1 spreads one aircraft over several message types. The connector caches
  the latest callsign, altitude, speed, track, vertical rate, squawk and
  on-ground flag per ICAO address. A position report with a fix emits an event
  carrying that state. Other lines only update the cache.
- A position report without latitude and longitude, or with them out of range,
  emits nothing. Its line stays pending for the next event.
- State persists across events. A field keeps its last value until a later line
  replaces it.
- The event timestamp is the time of receipt. SBS-1 timestamps come from the
  receiver's clock.
- The cache holds at most 10,000 aircraft. ICAO addresses come from the feed,
  so a spoofing sender cannot grow it further. At the cap the aircraft cached
  first is evicted.
- Pending lines per aircraft are capped at 64 lines and 16 KiB. Over the cap the
  oldest line is dropped, counted in `connector_dropped_carryforward_total`,
  and the next event carries `payload_truncated = true`.

## Limits

- Only SBS-1 text input. No Beast or raw Mode S decoding.
- Alert, emergency and SPI flags are not decoded.
