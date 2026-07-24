<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-mavlink

Ingress connector for **MAVLink** — the framed telemetry protocol most UAS/drone
autopilots and ground stations already speak. It decodes each vehicle position
into a canonical Ajar air track, seals it with the connector's Ed25519 key, and
publishes it to Core.

Nothing on the vehicle side changes: the connector reads the MAVLink the
autopilot or GCS already forwards.

## Model

```
MAVLink (UDP) ──▶ ajar-mavlink ──▶ canonical Event ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
 untrusted edge     decode+CRC       (mim:aircraft)   (Ed25519)         (mTLS to Core)
```

The connector holds no Core secrets — only its own signing key. Core trusts the
signature, not the pipe. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## Scope

Handles both MAVLink v1 (`0xFE`) and v2 (`0xFD`) framing and decodes the position
messages **GLOBAL_POSITION_INT (33)** and **GPS_RAW_INT (24)** — the vehicle's
WGS-84 position and heading (`id = mav:<sysid>`, `entity_type = mim:aircraft`).
Multiple vehicles on one stream stay distinct by system id. Every frame's CRC is
verified before any field is trusted. Other messages (heartbeats, status) are
well-formed but not mapped, so they are ignored, not dropped as errors.

## Configure & run

Copy [`mavlink.example.toml`](mavlink.example.toml). Autopilots and ground
stations commonly forward MAVLink over UDP:

```toml
[transport]
kind = "udp"
bind = "0.0.0.0:14550"
```

```bash
ajar-mavlink ./mavlink.toml
# production mTLS + health as per the repo README
```

## Security note

MAVLink is an untrusted edge: frames can be truncated, mis-framed, or hostile.
The frame is length-checked and its CRC (CRC-16/MCRF4XX with the per-message
CRC_EXTRA) verified before any field is read; the decoder never panics. Trust is
established downstream by the seal.

## Conformance

`cargo test` proves byte-identity to the SDK, that the seal verifies under the
published contract key, and a pinned mapping hash — and fuzzes the decoder against
thousands of arbitrary and MAVLink-shaped inputs (never panics). The decode is
checked against ground-truth v1 and v2 GLOBAL_POSITION_INT frames with correct
CRCs.
