<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-asterix

Ingress connector for **EUROCONTROL ASTERIX** — the air picture NATO air defence
(ACCS) and civil surveillance run on. One connector decodes the three air-picture
categories into canonical Ajar air tracks, seals each with the connector's Ed25519
key, and publishes to Core. Nothing on the surveillance side changes: it reads the
ASTERIX the radar / ground station already multicasts.

| Category | What it is | Position |
|---|---|---|
| **CAT021** | ADS-B target reports (cooperative traffic) | WGS-84, direct |
| **CAT048** | Monoradar target reports (primary + Mode S/SSR — sees non-cooperative traffic) | range/azimuth relative to the radar → geolocated against the configured site |
| **CAT062** | SDPS **system tracks** — the fused, recognised air picture | WGS-84, direct |

Together they round out the air picture: cooperative (CAT021), primary radar
(CAT048), and the fused track (CAT062).

## Model

```
ASTERIX (UDP multicast) ──▶ ajar-asterix ──▶ canonical Event(s) ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
     untrusted edge          decode            (mim:aircraft)     (Ed25519)        (mTLS to Core)
```

One datagram is one ASTERIX data block, which may contain **several** records — so
one frame produces several sealed events. The whole raw record is sealed verbatim
into `Event.payload`. The connector holds no Core secrets — only its own signing
key. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## How it decodes

A record begins with a variable-length **FSPEC** naming the items present, in the
fixed order of the category's **UAP** (User Application Profile). The engine is
category-generic: a length model per UAP item — including a recursive model for the
**compound** items (I048/130, I062/380 and friends, whose length depends on a
subfield bitmap) — lets it walk past any item to the next record. Each category
supplies a UAP table plus a small decoder; adding a category is a table, not new
parsing logic.

Decoded fields ride as attributes (Core's ontology governs which are kept) with
canonical units — `speed` in m/s (native knots in metadata), `course` in degrees,
`vertical_rate` in m/s. Native identity (ICAO 24-bit address, else `SAC:SIC:track`)
is preserved as `source_uid`.

**CAT048 geolocation.** Monoradar reports are range/azimuth relative to the radar.
Set the radar's site in config (`[sensor]`) and the connector forward-geolocates
each report onto the map; without it, the range/azimuth ride as metadata and the
event carries no absolute location. CAT021/CAT062 carry WGS-84 already and ignore
the setting.

> Validate the UAP against your feed's ASTERIX edition before operational use.
> Field layouts here are cross-checked against the python-asterix and Wireshark
> reference decoders. Categories other than 021/048/062 are ignored (not an error).

## Configure & run

Copy [`asterix.example.toml`](asterix.example.toml). ASTERIX is usually UDP
multicast on a surveillance LAN:

```toml
[transport]
kind = "udp-multicast"
bind = "0.0.0.0:8600"
group = "232.1.1.1"

# CAT048 only — the radar's own site, to geolocate its range/azimuth reports.
# [sensor]
# lat = 60.31
# lon = 24.97
```

```bash
ajar-asterix ./asterix.toml
# production mTLS + health as per the repo README
```

## Security note

ASTERIX is an untrusted edge and the decoder walks attacker-influenced FSPEC,
compound-bitmap, and REP/Explicit length fields, so every length is bounds-checked
before it is read; the decoder never panics and never emits a misaligned or
fabricated position. Trust is established downstream by the seal.

## Conformance

`cargo test` decodes hand-built CAT048 and CAT062 records that exercise the
compound walks (a wrong subfield length would misalign the record and fail the
test), checks the CAT062 event against Core's content contract and that the seal
verifies under the published contract key, and fuzzes the block/record walk against
thousands of arbitrary and category-shaped inputs (never panics).
