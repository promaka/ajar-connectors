<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-adsb

Ajar ingress connector for **ADS-B** aircraft reports in the **SBS-1 /
BaseStation** format — the line-delimited CSV every `dump1090` / `readsb`
receiver emits on TCP port 30003. It gives you a cooperative air picture
alongside the radar (ASTERIX) and drone (MAVLink) feeds.

## What it does

An SBS-1 stream fragments each aircraft across message types, so the connector
keeps a small, bounded per-ICAO state cache and emits a canonical
`mim:aircraft` track when a **position** arrives, enriched with that aircraft's
latest known identity and kinematics:

| SBS message | Fields taken |
|-------------|--------------|
| MSG,1 | callsign |
| MSG,2 (surface) / MSG,3 (airborne) | position, altitude → **emits a track** |
| MSG,4 | ground speed, track, vertical rate |
| MSG,6 | squawk |

The 24-bit **ICAO address** is emitted as a stable `source_uid` (and `icao`
metadata), so Core derives a per-airframe `track_id` and the console renders one
symbol per aircraft — never a merged blob.

Governed attribute keys (see [`../ATTRIBUTES.md`](../ATTRIBUTES.md)):
`affiliation`, `callsign`, `speed` (kt), `course` (deg), `vertical_speed` (m/s),
`squawk`, `on_ground`. Altitude rides in the event location (metres).

ADS-B carries no affiliation of its own — set `default_affiliation` (usually
`"neutral"`) in the config.

## Run

```sh
cp adsb.example.toml adsb.toml     # edit source_id, key, transport
ajar-adsb ./adsb.toml
```

Point `[transport]` at your receiver's SBS-1 output (`tcp-client` →
`host:30003`, `framing = "line"`), or use `tcp-server` to let the receiver push
to you. The signing key is generated with `scripts/gen-connector-key.sh` and its
public key registered with Core.

## Safety

The parser sits on an untrusted edge: every field is read defensively, every
failure is a typed `AdsbError` that the runtime counts and logs, and the cache
is bounded (FIFO, 10k aircraft) because the ICAO address is attacker-controllable.
Property tests assert it never panics on arbitrary input.
