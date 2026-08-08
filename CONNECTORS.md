<!-- SPDX-License-Identifier: Apache-2.0 -->
# Connector catalogue — which one for which system

Every connector turns one native feed into **signed, canonical Ajar events** — the
raw frame sealed verbatim with the connector's Ed25519 key, positions and kinematics
normalised to canonical units, native identifiers preserved. Pick a connector by the
**wire format your equipment speaks**, not by its make: a radar and a ground station
from different vendors that both emit ASTERIX use the same connector.

**Transport is configuration, not code.** Any connector reads from whatever delivers
its bytes — UDP multicast, TCP, serial, a tailed file, a watched directory, stdin, an
exec'd CLI, MQTT, or an HTTP poll — chosen in the `[transport]` block of its config.
So "my system outputs ASTERIX over UDP multicast" and "…over a TCP stream" are the
same connector with a different four-line transport section.

---

## Air

### `ajar-asterix` — EUROCONTROL ASTERIX (CAT021 / CAT048 / CAT062)
**Use it for** the surveillance air picture: cooperative traffic, primary/secondary
radar, and the fused recognised track.
**Systems that speak it:** primary and secondary surveillance radars (PSR / SSR /
Mode S) and air-defence radars (Thales, Indra, Leonardo, Hensoldt and others);
ADS-B ground stations (CAT021); air-traffic automation / SDPS and NATO ACCS, which
emit the fused **CAT062** system tracks. CAT048 monoradar reports are range/azimuth
from the radar and are geolocated against a configured `[sensor]` site.
**Typical transport:** UDP multicast on the surveillance LAN.

### `ajar-adsb` — ADS-B (SBS-1 / BaseStation)
**Use it for** cooperative air traffic from an ADS-B receiver feed.
**Systems that speak it:** software receivers `dump1090` / `readsb`, RTL-SDR and
Kinetic/FlightAware SBS-1 hardware, OpenSky feeders, and ADS-B ground sensors that
output the BaseStation (port 30003) line format.
**Typical transport:** TCP client to the receiver, or a tailed file.

---

## Maritime

### `ais-nmea` — AIS over NMEA 0183
**Use it for** the maritime surface picture.
**Systems that speak it:** shipborne Class A / Class B AIS transponders, coastal AIS
base stations and VTS, AIS receivers (em-trak, Comar, SRT, dAISy), and AIS
aggregators that re-emit NMEA sentences.
**Typical transport:** TCP client to an aggregator, serial from a receiver, or UDP.

---

## Land & ground

### `ajar-gmti` — STANAG 4607 (NATO GMTI)
**Use it for** ground moving-target radar — raw, un-associated detections.
**Systems that speak it:** airborne and ground GMTI radars and ISR platforms —
E-8 JSTARS, ASTOR / Sentinel, Reaper / Predator with a GMTI payload, Global Hawk
MP-RTIP — and any 4607-compliant ground station or exploitation system.
**Typical transport:** file / directory of captures, or a TCP/UDP feed of 4607 packets.

---

## ISR

### `ajar-klv` — STANAG 4609 / MISB ST 0601 (KLV)
**Use it for** full-motion-video metadata: platform and sensor position, slant range,
frame time — the telemetry embedded alongside ISR video.
**Systems that speak it:** UAS EO/IR turrets and gimbals (L3Harris WESCAM MX-series,
Teledyne FLIR), MISB-compliant FMV from Predator / Reaper / ScanEagle-class platforms,
and video-management / exploitation systems that carry KLV in an MPEG-TS stream.
**Typical transport:** UDP or file for extracted KLV, or exec from a TS demuxer.

### `ajar-stanag4676` — STANAG 4676 (NATO ISR Tracking, AEDP-12 Ed B)
**Use it for** the fused **track** layer above raw detections — recognised tracks
with a persistent identity across time. The natural complement to `ajar-gmti`
(detections) and `ajar-klv` (video).
**Systems that speak it:** ISR exploitation and tracking systems, GMTI and
motion-imagery trackers, and ground stations that output NITS `nitsRoot` track
messages.
**Typical transport:** TCP with length-delimited framing, or file.

---

## Unmanned systems

### `ajar-mavlink` — MAVLink
**Use it for** telemetry from small and commercial-derived UAS.
**Systems that speak it:** PX4 and ArduPilot autopilots (Pixhawk / Cube flight
controllers), ground stations such as QGroundControl and Mission Planner, and the
many COTS drones built on those stacks.
**Typical transport:** UDP, or serial from a radio link.

### `ajar-stanag4586` — STANAG 4586 (NATO UAS Control)
**Use it for** telemetry from the larger military UAS that speak the NATO UAS-control
Data Link Interface — the military counterpart to MAVLink. (It ingests vehicle-state
telemetry; it does not command vehicles.)
**Systems that speak it:** tactical / MALE UAS such as Gray Eagle, RQ-7 Shadow,
MQ-8 Fire Scout and Watchkeeper, and their ground control stations / vehicle-specific
modules (VSMs).
**Typical transport:** UDP between the VSM and the control system.

---

## Command & control / COP

### `ajar-tak-cot` — TAK / Cursor-on-Target (ingress)
**Use it for** the tactical-edge situational-awareness picture — friendly positions,
markers, and reports from end-user devices.
**Systems that speak it:** ATAK / WinTAK / iTAK end-user devices, TAK Server,
FreeTAK, and the many tactical apps and gateways that emit CoT XML.
**Typical transport:** UDP multicast (the SA broadcast default) or TCP.

### `ajar-tak-egress` — CoT egress relay (output)
**Use it for** the reverse direction: pushing governed, provenance-checked tracks
**back out** to a TAK Server so ATAK users see the fused picture. This is an egress
relay, not an ingest connector.
**Feeds:** a TAK Server's streaming input → ATAK / WinTAK clients downstream.
**Typical transport:** TLS client to the TAK Server.

---

## Anything else

### `ajar-generic` — config-driven JSON / CSV / NMEA-like
**Use it for** any modern feed that has no dedicated connector — map its fields to
canonical events in the config, with **no code**.
**Systems that speak it:** vendor REST/JSON APIs, national C2 exports, IoT and sensor
buses, scheduled CSV drops — anything that emits line-delimited JSON/CSV or a simple
record format.
**Typical transport:** HTTP poll, MQTT, watched directory, tailed file, stdin, or exec.

---

## Choosing quickly

| If your system outputs… | Use |
|---|---|
| Air surveillance radar / SDPS tracks | `ajar-asterix` |
| ADS-B receiver lines (BaseStation) | `ajar-adsb` |
| AIS / NMEA sentences | `ais-nmea` |
| GMTI radar (STANAG 4607) | `ajar-gmti` |
| FMV metadata (KLV / MISB 0601) | `ajar-klv` |
| ISR tracks (STANAG 4676) | `ajar-stanag4676` |
| Small / commercial drone telemetry (MAVLink) | `ajar-mavlink` |
| Military UAS telemetry (STANAG 4586) | `ajar-stanag4586` |
| TAK / CoT | `ajar-tak-cot` (in) · `ajar-tak-egress` (out) |
| Modern JSON / CSV, no dedicated connector | `ajar-generic` |

Don't see your format? If it's a released, testable standard it may be a candidate —
see [FEASIBILITY.md](FEASIBILITY.md) for how we decide what to build (and what we
deliberately don't). If it's a modern JSON/CSV feed, `ajar-generic` likely covers it
today with a config change.
