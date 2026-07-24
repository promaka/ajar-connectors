<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-asterix

Ingress connector for **EUROCONTROL ASTERIX CAT021** — the ADS-B target-report
category carried on most surveillance networks. It decodes each target's WGS-84
position into a canonical Ajar air track, seals it with the connector's Ed25519
key, and publishes it to Core.

Nothing on the surveillance side changes: the connector reads the ASTERIX the
radar/ADS-B ground station already multicasts.

## Model

```
ASTERIX CAT021 (UDP multicast) ──▶ ajar-asterix ──▶ canonical Event(s) ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
        untrusted edge               decode           (mim:aircraft)      (Ed25519)         (mTLS to Core)
```

One datagram is one ASTERIX data block, which may contain **several** target
records — so one frame produces several sealed events. The connector holds no Core
secrets — only its own signing key. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## Scope

Decodes **CAT021 (Edition 2.x)** ADS-B position reports: item I021/130 (and the
high-resolution I021/131) WGS-84 position, keyed by target address (I021/080, an
ICAO 24-bit id) or track number (I021/161) — `entity_type = mim:aircraft`. The
decoder carries the CAT021 UAP length table so it can walk past any standard data
item to the next record; the few compound items it does not length-model (Met,
Trajectory Intent, Data Ages) make it **stop and report** rather than risk a
misaligned position — it fails closed.

> Validate the UAP against your feed's ASTERIX edition before operational use.
> Categories other than 021 are ignored (not an error).

## Configure & run

Copy [`asterix.example.toml`](asterix.example.toml). ASTERIX is usually UDP
multicast on a surveillance LAN:

```toml
[transport]
kind = "udp-multicast"
bind = "0.0.0.0:8600"
group = "232.1.1.1"
```

```bash
ajar-asterix ./asterix.toml
# production mTLS + health as per the repo README
```

## Security note

ASTERIX is an untrusted edge and the decoder walks attacker-influenced length
fields, so every length is bounds-checked before it is read; the decoder never
panics and never emits a misaligned or fabricated position. Trust is established
downstream by the seal.

## Conformance

`cargo test` proves byte-identity to the SDK, that the seal verifies under the
published contract key, and a pinned mapping hash — decodes single- and
multi-record ground-truth CAT021 blocks — and fuzzes the block/record walk against
thousands of arbitrary and CAT021-shaped inputs (never panics).
