<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-sapient — SAPIENT (BSI Flex 335) ingress

Ingress connector for **SAPIENT**, the UK MOD interface between autonomous
sensor edge nodes and a fusion node, published as BSI Flex 335 and used for
counter-UAS. It takes the messages a SAPIENT system exchanges, protobuf with a
length prefix over TCP, and turns each report into a signed canonical Ajar
event.

Two roles, one binary:

- **`dmm`**: the connector *is* the fusion node's message handler. Edge nodes
  connect to it, register, are acknowledged, and report. Nothing on the sensor
  side changes; the sensor is pointed at the connector's address instead of a
  fusion node's.
- **`subscriber`**: the connector listens to a fusion node's output, or replays
  a capture, and only reads.

## Model

```
edge nodes ──TCP──▶ ajar-sapient ──▶ canonical Event ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
 (register, status,  decode + map     (sapient:* types)  (Ed25519)        (mTLS to Core)
  detect, alert)     + acknowledge
```

The connector holds no Core secrets, only its own signing key. Core trusts the
signature, not the pipe.

## What it emits

| SAPIENT message | Event type | Position | Governed attributes |
|---|---|---|---|
| Detection report | `sapient:detection`, or `sapient:track` when the report carries track information | the report's WGS-84 position, or range and bearing geolocated against the node's last reported position | `speed` (m/s), `course` (deg), `vertical_rate` (m/s), `object_class`, `sapient_classification`, `sapient_classification_confidence`, `sapient_behaviour`, `sapient_state`, `position_accuracy_h_m` (from the range error) |
| Status report | `sapient:sensor-status` | the node's position | `sapient_system`, `sapient_mode`, `sapient_power_level`, `sapient_node_type` |
| Registration | `sapient:sensor-status` | none | `sapient_node_type`, `update_interval_s` |
| Alert | `sapient:alert` | the alert's position, if given | `sapient_alert_type`, `sapient_alert_status`, `sapient_priority`, `sapient_ranking` |
| Task, acknowledgements, error | none | | counted under `sapient_unmapped_total` |

Every event seals the message's protobuf bytes verbatim in `payload`. The
detection confidence becomes the event's `confidence`. The node id and object
id together are the `source_uid`, so each tracked object stays its own track
across reports; the node id alone is the `source_uid` of its status events.

**Units.** SAPIENT velocities are ENU vectors in the units the node declared
at registration, metres per second or kilometres per hour; both come out as
`speed` in metres per second and `course` in degrees true. Positions in
radians are converted; a UTM position is not, and rides as metadata with its
zone. A range-and-bearing report needs the node's position, which arrives in
its status report; until then, or when the bearing datum is magnetic, the
range and bearing ride as metadata, the event has no location, and
`sapient_unlocated_total` counts it.

**Types.** The `sapient:` types are not in the vendored MIM ontology. They
are an operator-registered fragment, [`sapient.types.json`](sapient.types.json)
beside this README, parented to `mim:object`, `mim:sensor` and `mim:action`.
The Core operator registers it once:

```sh
ajar onboard sapient-fusion-1 --mint --types sapient: --protocol sapient \
  --type-spec sapient.types.json ...
```

An `[entity_map]` can send a classified object to a MIM type instead, for
example `"UAV" = "mim:aircraft"`, which gives it a standard symbol; the
SAPIENT-specific attributes then ride as metadata, since a MIM type does not
govern them.

## Configure and run

```sh
cp sapient.example.toml sapient.toml   # edit source_id, key path, [options] and [transport]
ajar-sapient ./sapient.toml
ajar-sapient --profile ./sapient.toml  # the document your operator registers
```

`[options]`:

| Key | Values | Default |
|---|---|---|
| `role` | `dmm`, `subscriber` | `dmm` |
| `node_id` | this node's UUID, carried in every acknowledgement | a fresh UUID at start-up |

The `dmm` role needs `[transport] kind = "tcp-server"`. The `subscriber` role
takes any transport with `framing = "length-u32le"`, the standard's 4-byte
little-endian prefix: `tcp-client` for a fusion node's output, `file` with
`from_start = true` for a capture.

## Replay a capture

```toml
[options]
role = "subscriber"

[transport]
kind = "file"
path = "/var/ajar/captures/sapient-bench.bin"
from_start = true
framing = "length-u32le"
```

The connector reads the recording from the start as if the nodes were live,
then keeps following the file for appends. `tests/data/sapient-capture.bin`
is a small bench scenario in this form: a radar registers, reports its
position, follows a UAV closing from the north-east, and raises an alert.

## Version

Built against BSI Flex 335 v2.0, the published schema. The v1.0 schema is
compiled into the wire crate behind its `v1` feature; a site still on it is a
build-time choice, made once the version in use is known.

## Conformance

`cargo test -p ajar-sapient` proves a detection decodes to one located event
in the contract's units, that the message is sealed verbatim in the payload,
that the seal verifies under the published contract key, that the bench
capture replays end to end through the `file` transport with every report
accepted, that a registration is acknowledged, and that hostile bytes never
panic, with mutated real messages and random bytes alike.
