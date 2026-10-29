<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-asterix

Ingress connector for **EUROCONTROL ASTERIX**, the surveillance data format of
civil ATC and NATO air defence. It reads the ASTERIX a radar head, ADS-B ground
station or tracker already sends, and publishes signed track events and radar
status events to Core. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## Input

A frame is one datagram holding one or more data blocks, `CAT | LEN | record...`.
Every block in the datagram is decoded. A record is an **FSPEC** bitmap naming
the items present, then those items in the order of the category's **UAP**
(User Application Profile).

| Category | Content | Position |
|---|---|---|
| CAT010 Ed 1.1 | Monosensor surface movement: airport surface, and sea surface from coastal and naval radars | WGS-84, or polar or Cartesian from the sensor |
| CAT021 Ed 2.x | ADS-B target reports | WGS-84 |
| CAT034 Ed 1.27 | Monoradar service messages: north markers, sector crossings, status, jamming strobes | the radar's own, if reported |
| CAT048 | Monoradar target reports, primary and Mode S/SSR | slant range and azimuth from the radar |
| CAT062 | SDPS system tracks, the fused picture | WGS-84 |

A block of any other category is skipped and counted in
`asterix_ignored_blocks_total`. The blocks after it still decode.

Each UAP item has a length model, including the compound items (I048/130,
I062/380, I062/500 and others), so the walk steps past items it does not
decode. The exceptions are listed under Limits.
Validate the UAP against your feed's edition before operational use.

ASTERIX is usually UDP multicast on a surveillance LAN (`udp-multicast`).
`pcap-replay` replays a capture, and `dds` reads ASTERIX blocks from a DDS topic.

## Output

### Track events

One event per positioned target record of CAT010, CAT021, CAT048 or CAT062.

| Category | Entity type |
|---|---|
| CAT021, CAT048, CAT062 | `mim:aircraft` |
| CAT010 | `[entity_map] cat010` if set; else `mim:land-vehicle` with a vehicle fleet (I010/300); else `mim:aircraft` with an ICAO address or callsign; else `mim:object` |

Identity, first match:

| Record carries | `source_uid` | `alt_id` | `alt_id_standard` |
|---|---|---|---|
| ICAO address | `icao:<6 hex>` | `<6 hex>` | `ICAO24` |
| track number | `asterix:<cat>:<sac>:<sic>:<track>` | `<cat>:<sac>:<sic>:<track>` | `ASTERIX` |
| neither | `asterix:<cat>:<sac>:<sic>` | none | none |

Scoping the track number by category and SAC/SIC keeps two radars' track 7,
or one site's CAT010 and CAT062 track 7, apart.

| Attribute | Unit | CAT010 | CAT021 | CAT048 | CAT062 |
|---|---|---|---|---|---|
| `speed` | m/s | I010/200 or /202 | I021/160 | I048/200 | I062/185 |
| `course` | deg | I010/200 or /202 | I021/160 | I048/200 | I062/185 |
| `vertical_rate` | m/s | | | | I062/220 |
| `callsign` | | I010/245 | I021/170 | I048/240 | I062/245, I062/380 ID |
| `squawk` | four octal digits | I010/060 | I021/070 | I048/070 | I062/060 |
| `position_accuracy_h_m` | m | I010/500 | | | I062/500 APC |
| `position_accuracy_v_m` | m | | | | I062/500 ABA |
| `speed_accuracy` | m/s | | | | I062/500 ATV |
| `environment` | | `cat010_domain` | | | |
| `hostility` | | `default_hostility` | same | same | same |
| `alt_id`, `alt_id_standard` | | see identity | | | |

`squawk` and `environment` are attributes only where the entity type declares
them (`squawk` on `mim:aircraft`, `environment` on `mim:object`); otherwise
they go to metadata. The accuracy attributes are the root sum square of the
per-axis sigmas. A sum of zero means the sender left the field blank, and no
attribute is emitted. `position_accuracy_v_m` needs an altitude on the event.

Location is WGS-84, with the altitude in metres:

| Category | Latitude, longitude | Altitude |
|---|---|---|
| CAT010 | I010/041, else I010/040 or /042 geolocated against `[sensor]` | I010/091, else I010/090 |
| CAT021 | I021/131, else I021/130 | I021/140, else I021/145 |
| CAT048 | I048/040 geolocated against `[sensor]` | I048/090 |
| CAT062 | I062/105 | I062/136 |

An event without an absolute position carries no location, see Behaviour.

| Metadata | Content |
|---|---|
| `source_uid` | see identity |
| `asterix_category` | 10, 21, 48 or 62 |
| `speed_kn`, `vertical_rate_ftmin`, `altitude_ft` | native values |
| `time_of_day_s` | seconds since UTC midnight (I010/140, I048/140, I062/070) |
| `range_nm`, `azimuth_deg` | CAT048 or CAT010 polar position, when not geolocated |
| `x_m`, `y_m` | CAT010 Cartesian offset east and north, when not geolocated |
| `position_sd_x_m`, `position_sd_y_m` | per-axis position sigma |
| `report_type` | I010/020 sensor technique, e.g. `psr`, `ads-b` |
| `vehicle_fleet` | I010/300, e.g. `fire`, `tug` |
| `target_length_m`, `target_width_m`, `target_orientation_deg` | I010/270 |
| `emitter_category` | I021/020, e.g. `heavy`, `uav` |

The payload is the record's bytes, from its FSPEC to its last item.

### Radar status events

CAT034 north markers and jamming strobes (standard, SSR and Mode S) each emit
one event about the radar. The entity type is `mim:sensor`, or
`[entity_map] cat034`. `source_uid` is `asterix:radar:<sac>:<sic>`; `alt_id`
is `<sac>:<sic>` under `ASTERIX`. Location is I034/120, else the `[sensor]`
site, else none.

| Attribute | Unit | Source |
|---|---|---|
| `scan_period_s` | s | I034/041 antenna rotation period |
| `update_interval_s` | s | I034/041, north marker only |
| `coverage_bearing_start_deg`, `coverage_bearing_end_deg` | deg | I034/100 azimuths, north marker only |
| `detection_range_m` | m | I034/100 end range, north marker only |
| `hostility` | | `default_hostility` |

These go to metadata instead when the configured entity type does not declare
them. On a jamming strobe, I034/100 is the jammed sector, not coverage, so it
stays in metadata.

| Metadata | Content |
|---|---|
| `asterix_category` | 34 |
| `message_type` | `north-marker`, `jamming-strobe`, `ssr-jamming-strobe`, `mode-s-jamming-strobe` |
| `time_of_day_s` | I034/030 |
| `rotation_period_s` | I034/041 |
| `sector` | I034/020, 360/256 deg each |
| `window_range_start_nm`, `window_range_end_nm`, `window_azimuth_start_deg`, `window_azimuth_end_deg` | I034/100 |
| `nogo`, `rdp_overload`, `xmt_overload`, `monitoring_disconnected`, `time_source_invalid`, `psr_overload`, `ssr_overload`, `mds_overload` | the radar's last reported I034/050 status, each once reported |

The payload is the CAT034 record's bytes.

## Configuration

Copy [`asterix.example.toml`](asterix.example.toml).

| Key | Default | Effect |
|---|---|---|
| `[sensor] lat`, `lon` | unset | The radar site. CAT048 and sensor-relative CAT010 positions are geolocated against it; CAT034 events without I034/120 are located at it. |
| `[sensor] alt_m` | 0 | Site height, metres above the WGS-84 ellipsoid. Used for the CAT048 slant-range correction and CAT034 location. |
| `[entity_map] cat010` | unset | Entity type for every CAT010 plot, e.g. `mim:vessel` for a coastal radar. |
| `[entity_map] cat010_domain` | unset | `environment` for the plots: `SURFACE`, `LAND`, `SUBSURFACE` or `AIR`. Checked against the ontology at startup; an unknown value refuses to start. |
| `[entity_map] cat034` | `mim:sensor` | Entity type of the radar status events. |
| `default_hostility` | unset | `hostility` on every event. ASTERIX carries none. |

```sh
ajar-asterix ./asterix.toml
ajar-asterix ./asterix.toml --profile   # print the profile to register, then exit
```

## Behaviour

- **Geolocation.** CAT048 reports are slant range and azimuth from the radar.
  With `[sensor]` set, the slant range is projected to ground range using the
  flight level as height above the site, then stepped along the azimuth on a
  spherical earth. Without a flight level the slant range is used as ground
  range. A return steeper than vertical lands on the site. CAT010 polar ranges
  are ground ranges and need no correction; CAT010 Cartesian offsets are x east,
  y north. Without `[sensor]`, these records carry no location and the
  measurement rides in metadata.
- **No position, no event.** A target record without an absolute or
  sensor-relative position is not published. A CAT010 record is a track only
  when I010/000 is 1 (target report).
- **Simulated and test targets.** A CAT048 or CAT010 report with SIM, TST or
  RAB set in its target report descriptor is counted in
  `asterix_test_targets_total` and not published.
- **Invalid codes.** A CAT048 or CAT010 Mode 3/A code or flight level with the
  V or G bit set is omitted.
- **Radar status.** Every CAT034 record updates a status kept per radar
  (SAC/SIC). A status field keeps its last reported value until a later record
  replaces it, so each north marker carries the whole picture. Sector crossings
  update status and are counted, not published.
- **Timestamp.** Every event is stamped with the time of receipt. The ASTERIX
  time of day is kept in `time_of_day_s`.
- **Errors.** A block whose length runs past the datagram, a truncated item, or
  an item the decoder cannot measure fails the whole datagram, and none of its
  events are published.

| Counter | Counts |
|---|---|
| `asterix_ignored_blocks_total` | blocks of an undecoded category |
| `asterix_test_targets_total` | simulated, test and field-monitor reports |
| `asterix_north_markers_total` | CAT034 north markers |
| `asterix_sector_crossings_total` | CAT034 sector crossings |
| `asterix_jamming_strobes_total` | CAT034 jamming strobes of any kind |
| `asterix_radar_degraded_total` | north markers while the radar reports NOGO or an overload |

## Limits

- Items not listed above are not decoded. They stay in the payload.
- I021/220 (met information), I021/110 (trajectory intent) and I021/295 (data
  ages) are not length-modelled. A CAT021 record that contains one fails its
  datagram. The same holds for the spare FRNs of CAT062.
- CAT021 time of applicability and CAT062 geometric and barometric altitudes
  (I062/130, I062/135) are not decoded.

## Conformance

`cargo test -p ajar-asterix` decodes hand-built CAT010, CAT034, CAT048 and
CAT062 records, including the compound walks, where a wrong subfield length would misalign the
record. `tests/conformance.rs` checks a CAT062 event against Core's content
contract and that its seal verifies under the published contract key.
`tests/fuzz.rs` runs arbitrary and category-shaped input through the decoder.
