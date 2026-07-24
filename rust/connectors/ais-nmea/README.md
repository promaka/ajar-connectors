<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-ais-nmea

Ingress connector for **AIS** (Automatic Identification System) — the maritime
transponder feed that ships, coastal stations, and AIS receivers already
broadcast as NMEA 0183 `!AIVDM` sentences. It decodes each position report into a
canonical Ajar vessel track, seals it with the connector's Ed25519 key, and
publishes it to Core.

Nothing on the AIS side changes: the connector reads the sentences the receiver
already emits.

## Model

```
AIS (NMEA over TCP/UDP) ──▶ ajar-ais-nmea ──▶ canonical Event ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
       untrusted edge          decode          (mim:vessel)     (Ed25519)         (mTLS to Core)
```

The connector holds no Core secrets — only its own signing key. Core trusts the
signature, not the pipe. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## Scope

Decodes the **position reports** — AIS message types 1, 2, 3 (class A) and 18, 19
(class B) — which carry the MMSI and WGS-84 position that become a vessel track
(`id = mmsi:<n>`, `entity_type = mim:vessel`, course as an attribute). Multi-part
sentences are reassembled. Other message types (static/voyage data, safety) are
well-formed but not mapped, so they are ignored, not dropped as errors.

## Configure & run

Copy [`ais-nmea.example.toml`](ais-nmea.example.toml). AIS usually arrives one of
two ways, both just config:

```toml
[transport]
kind = "tcp-client"                    # connect out to an aggregator / ship-network feed
connect = "ais-feed.example.mil:5631"
# or:
# kind = "udp"                         # a local receiver that UDP-broadcasts sentences
# bind = "0.0.0.0:10110"
```

```bash
ajar-ais-nmea ./ais-nmea.toml
# production mTLS + health as per the repo README
export AJAR_TLS_CA=… AJAR_TLS_CERT=… AJAR_TLS_KEY=… AJAR_HEALTH_ADDR=0.0.0.0:9110
```

## Security note

AIS is an untrusted edge: sentences can be malformed, mis-checksummed, or hostile.
Every sentence's NMEA checksum is verified, the 6-bit payload is bounds-checked,
and the parser never panics — every failure is a typed error that is counted and
logged. Trust is established downstream by the seal.

## Conformance

`cargo test` proves byte-identity to the SDK, that the seal verifies under the
published contract key, and a pinned mapping hash — and fuzzes the decoder against
thousands of arbitrary and AIVDM-shaped inputs (never panics). The decode is
checked against a real, independently-verified `!AIVDM` sentence (MMSI 227006760).
