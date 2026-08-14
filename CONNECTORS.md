<!-- SPDX-License-Identifier: Apache-2.0 -->
# Connector catalogue

Every connector turns one native feed into signed, canonical Ajar events. The raw
frame is sealed verbatim with the connector's Ed25519 key, positions and kinematics
are normalised to canonical units, and native identifiers are preserved.

Pick by the wire format your equipment speaks rather than by its make. A radar and a
ground station from different vendors that both emit ASTERIX use the same connector.

Transport is configuration. Any connector reads from whatever delivers its bytes,
chosen in the `[transport]` block of its config: UDP multicast, TCP, an HTTP endpoint
receiving webhook deliveries, serial, a tailed file, a watched directory, stdin, an
exec'd CLI, MQTT or an HTTP poll. A system that
outputs ASTERIX over UDP multicast and one that sends it over a TCP stream use the
same connector with a different four-line transport section.

## Air

### `ajar-asterix` (EUROCONTROL ASTERIX, CAT021 / CAT048 / CAT062)

The surveillance air picture: cooperative traffic from ADS-B ground stations
(CAT021), primary and secondary radar returns (CAT048), and the fused recognised
track from an SDPS (CAT062). Primary and secondary surveillance radars (PSR, SSR,
Mode S) and air-defence radars from Thales, Indra, Leonardo, Hensoldt and others
emit it, as does NATO ACCS. CAT048 reports carry range and azimuth relative to the
radar, so set the radar's position in `[sensor]` to geolocate them. Usually arrives
as UDP multicast on the surveillance LAN.

### `ajar-adsb` (ADS-B, SBS-1 / BaseStation)

Cooperative air traffic from an ADS-B receiver. Covers the BaseStation format on
port 30003, as produced by `dump1090` and `readsb`, RTL-SDR setups, Kinetic and
FlightAware SBS-1 hardware, and OpenSky feeders. Connect over TCP to the receiver,
or tail its output file.

## Maritime

### `ais-nmea` (AIS over NMEA 0183)

The maritime surface picture. Class A and Class B shipborne transponders, coastal
AIS base stations and VTS installations, receivers from em-trak, Comar, SRT and
dAISy, and the aggregators that re-emit their sentences. Usually a TCP client to an
aggregator; serial or UDP when reading a receiver directly.

## Land and ground

### `ajar-gmti` (STANAG 4607, NATO GMTI)

Ground moving-target radar, as raw un-associated detections rather than tracks.
Fielded on airborne and ground GMTI platforms including E-8 JSTARS, ASTOR and
Sentinel, Reaper and Predator carrying a GMTI payload, and Global Hawk MP-RTIP, plus
any 4607-compliant ground station or exploitation system. Reads a directory of
captures, or a live TCP or UDP feed of 4607 packets.

## ISR

### `ajar-klv` (STANAG 4609 / MISB ST 0601)

The metadata embedded alongside full-motion video: platform and sensor position,
slant range, frame time. Produced by UAS EO/IR turrets such as the L3Harris WESCAM
MX series and Teledyne FLIR gimbals, by MISB-compliant FMV from Predator, Reaper and
ScanEagle-class platforms, and by video-management systems carrying KLV in an MPEG-TS
stream. Point it at extracted KLV over UDP or file, or exec a TS demuxer.

### `ajar-stanag4676` (STANAG 4676, NATO ISR Tracking, AEDP-12 Ed B)

Fused ISR tracks: recognised objects with an identity that persists across
observations. It sits above `ajar-gmti`, which gives you the raw detections, and
complements the video metadata from `ajar-klv`. Emitted by ISR exploitation and
tracking systems, by GMTI and motion-imagery trackers, and by ground stations
producing NITS `nitsRoot` messages. TCP with length-delimited framing, or file.

## Unmanned systems

### `ajar-mavlink` (MAVLink)

Telemetry from small and commercial-derived UAS. PX4 and ArduPilot autopilots on
Pixhawk and Cube flight controllers, ground stations including QGroundControl and
Mission Planner, and the many COTS drones built on those stacks. UDP, or serial over
a radio link.

### `ajar-stanag4586` (STANAG 4586, NATO UAS Control)

Telemetry from the larger military UAS that speak the NATO UAS-control Data Link
Interface. Fielded on tactical and MALE platforms such as Gray Eagle, RQ-7 Shadow,
MQ-8 Fire Scout and Watchkeeper, and on their vehicle-specific modules. This
connector ingests vehicle state; it does not command aircraft. UDP between the VSM
and the control system.

## Command and control

### `ajar-tak-cot` (TAK / Cursor-on-Target, ingress)

The tactical-edge situational-awareness picture: friendly positions, markers and
reports from end-user devices. ATAK, WinTAK and iTAK clients, TAK Server, FreeTAK,
and the many tactical apps and gateways that emit CoT XML. UDP multicast is the
usual SA broadcast; TCP where a server pushes to you.

### `ajar-tak-egress` (CoT egress relay, output)

The reverse direction. Relays governed, provenance-checked tracks back out to a TAK
Server so ATAK users see the fused picture. This is an egress relay rather than an
ingest connector, and it connects over TLS to the server's streaming input.

## Anything else

### `ajar-generic` (config-driven JSON, CSV and NMEA-like)

Any feed without a dedicated connector, mapped to canonical events in configuration
rather than in code. Suits vendor REST and JSON APIs, national C2 exports, IoT and
sensor buses, and scheduled CSV drops: anything emitting line-delimited JSON, CSV or
a simple record format. Runs on an HTTP poll, MQTT, a watched directory, a tailed
file, stdin or exec.

## Choosing quickly

| If your system outputs | Use |
|---|---|
| Air surveillance radar or SDPS tracks | `ajar-asterix` |
| ADS-B receiver lines (BaseStation) | `ajar-adsb` |
| AIS / NMEA sentences | `ais-nmea` |
| GMTI radar (STANAG 4607) | `ajar-gmti` |
| FMV metadata (KLV / MISB 0601) | `ajar-klv` |
| ISR tracks (STANAG 4676) | `ajar-stanag4676` |
| Small or commercial drone telemetry (MAVLink) | `ajar-mavlink` |
| Military UAS telemetry (STANAG 4586) | `ajar-stanag4586` |
| TAK / CoT | `ajar-tak-cot` inbound, `ajar-tak-egress` outbound |
| Modern JSON or CSV with no dedicated connector | `ajar-generic` |

Don't see your format? If it is a released and testable standard it may be a
candidate; [FEASIBILITY.md](FEASIBILITY.md) sets out how we decide what to build and
what we deliberately leave alone. If it is a modern JSON or CSV feed, `ajar-generic`
most likely covers it today with a configuration change.
