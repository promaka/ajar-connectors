<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-stanag4586

Ingress connector for **STANAG 4586** (NATO UAS Control) — the coalition standard
for military UAS interoperability. STANAG 4586 defines the full **UAS Control System
(UCS)** interface across Levels of Interoperability 1–5, from telemetry receipt up to
flight and payload control and control-station handover. **This connector ingests the
telemetry** — the vehicle-state reports on the **Data Link Interface (DLI)**, sent
from a vehicle-specific module (VSM) to the Core UCS (CUCS) — as canonical Ajar
tracks, sealed with the connector's Ed25519 key. It is an *ingest* connector: it does
not command or control vehicles.

Where `ajar-mavlink` ingests telemetry from small and commercial-derived UAS, this
ingests it from the larger tactical / MALE platforms and ground stations that speak
4586 for NATO interoperability.

## Model

```
STANAG 4586 DLI (UDP) ──▶ ajar-stanag4586 ──▶ canonical Event(s) ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
     untrusted edge        decode                (mim:drone)        (Ed25519)        (mTLS to Core)
```

A datagram may pack **several messages** back to back; each has its own checksum, so
one datagram can produce several sealed events. The whole raw message (wrapper +
body + checksum) is sealed verbatim into `Event.payload`. The connector holds no
Core secrets — only its own signing key. See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## The wire, exactly

Every message is a fixed 30-byte header + body + 4-byte checksum footer, **big-endian
throughout** with IEEE-754 singles/doubles:

```
IDD version    10 bytes  null-terminated ASCII (document edition)
instance id     u32
message type    u32       1..<2000 standard, >2000 vehicle-specific
message length  u32       number of bytes in the body
stream id       u32
packet seq      u32       (unused, = -1)
<body>          length bytes
checksum        u32       byte-wise unsigned sum of all preceding bytes
```

> **Byte order is the trap.** The most active open reference implementation packs
> its structs in native (little-endian) order, contradicting the spec's mandated
> big-endian. The decoder here follows the **published NATO UNCLASSIFIED Edition 2
> field tables**, which are ground truth — not any one implementation.

## What it decodes

v1 decodes **Message #101 Inertial States** — the vehicle's full kinematic state,
sent regularly to the CUCS and exactly what populates a track:

- **Position** — latitude/longitude (radians on the wire → degrees) + altitude, with
  the altitude reference (pressure / baro / AGL / WGS-84) in metadata.
- **Kinematics** — ground `speed` and `course` derived from the North/East/Down
  velocity vector; `vertical_rate` (climb-positive) from the down component; native
  components preserved. `heading` (where the platform points) comes from yaw and is
  kept **distinct** from `course` (track over ground), per ADR-0019.
- **Attitude** — roll/pitch as metadata; yaw as `heading`.
- **Identity** — the vehicle id becomes `source_uid` (`s4586:vehicle:<id>`).

Speeds are m/s, angles degrees. 4586 carries no affiliation, so the operator asserts
one in config (own-force UAS are typically `friendly`). Other message types are
validated at the wrapper and skipped (not yet mapped) — a later pass extends coverage
without touching the wire.

## Configure & run

Copy [`stanag4586.example.toml`](stanag4586.example.toml). The DLI is usually UDP:

```toml
source_id = "uas-vsm-1"
nats_url  = "nats://127.0.0.1:4222"
signing_key_path = "/etc/ajar/uas-vsm-1.key"
default_affiliation = "friendly"

[transport]
kind = "udp"
bind = "0.0.0.0:4586"
```

```bash
ajar-stanag4586 ./stanag4586.toml
# production mTLS + health as per the repo README
```

## Security note

4586 is an untrusted edge and the decoder walks attacker-influenced message-length
and checksum fields across a multi-message datagram, so every length is bounds- and
overflow-checked, each message's checksum is validated fail-closed, and a lying
length halts the walk rather than reading out of bounds. The decoder never panics and
never emits a misaligned or fabricated position. Trust is established downstream by
the seal.

## Conformance

`cargo test` decodes a hand-built #101 Inertial States message (big-endian, correct
checksum) and checks position, derived kinematics, heading-vs-course, the Unix-epoch
timestamp, and identity; verifies the event against Core's content contract and that
the seal verifies under the published contract key; confirms two messages in one
datagram yield two events, and that corrupt checksums, lying lengths, and short
bodies are rejected without panicking; and fuzzes the walk against thousands of
arbitrary and wrapper-shaped inputs.

The message model is implemented from the public NATO UNCLASSIFIED STANAG 4586
Edition 2 field tables. An open reference implementation was consulted **only** to
disambiguate the message-wrapper length; no code was copied (it is GPL-licensed), and
its native-endian packing was **not** followed — the big-endian field tables are
ground truth.
