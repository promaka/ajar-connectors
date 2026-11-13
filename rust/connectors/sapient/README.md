<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-sapient: SAPIENT (BSI Flex 335) ingress

Ingress connector for **SAPIENT**, the UK MOD interface between autonomous
sensor edge nodes and a fusion node, published as BSI Flex 335 and used for
counter-UAS. It reads the messages a SAPIENT system exchanges and turns each
registration, status report, detection report and alert into a signed Ajar
event on `ajar.ingest.<source_id>`.

One binary plays one of two roles:

- **`dmm`**: the connector takes the place of the fusion node's message
  handler (the DMM in BSI Flex 335 terms). Edge nodes connect to it, register,
  are acknowledged, and report. The sensors need no change beyond the address
  they connect to.
- **`subscriber`**: the connector reads a fusion node's output, or replays a
  capture, and sends nothing back.

## Input

BSI Flex 335 v2.0 protobuf messages, each framed by a 4-byte little-endian
length prefix. A message above 64 KiB is refused.

| Message | Handling |
|---|---|
| `DetectionReport` | one event |
| `StatusReport` | one event |
| `Registration` | one event; acknowledged in the `dmm` role |
| `Alert` | one event |
| `RegistrationAck`, `Task`, `TaskAck`, `AlertAck`, `Error` | no event; counted in `sapient_unmapped_total` |

A frame that does not decode, or an envelope without content, is refused with
an error.

Transports:

- `dmm` role: `[transport] kind = "tcp-server"` only; any other kind is refused
  at start-up. The connector owns the connections and always applies the
  standard's framing.
- `subscriber` role: any transport. A stream transport takes
  `framing = "length-u32le"`; any other framing logs a warning at start-up.
  Use `tcp-client` for a fusion node's output, or `file` with
  `from_start = true` for a capture.

## Output

| Message | Entity type | Location | `source_uid` |
|---|---|---|---|
| Detection report | `sapient:track` when the report carries track information, else `sapient:detection` | the report's position, or range and bearing geolocated against the node | `<node_id>:<object_id>` |
| Status report | `sapient:sensor-status` | the node's position | `<node_id>` |
| Registration | `sapient:sensor-status` | none | `<node_id>` |
| Alert | `sapient:alert` | the alert's position, if given | `<node_id>:<alert_id>` |

The node id and object id together keep each tracked object its own track
across reports. No governed identity (`alt_id`) is emitted. Every event's
`payload` is the message's protobuf bytes, without the length prefix. The
event time is the envelope's timestamp, or the receive time when it has none.

Attributes:

| Attribute | Unit | Message | Source |
|---|---|---|---|
| `speed` | m/s | detection | horizontal ENU velocity |
| `course` | degrees true, 0 to 360 | detection | direction of the horizontal ENU velocity |
| `vertical_rate` | m/s | detection | up rate |
| `object_class`, `sapient_classification` | | detection | the classification with the highest confidence |
| `sapient_classification_confidence` | 0 to 1 | detection | that classification's confidence |
| `sapient_behaviour` | | detection | the first behaviour with a type |
| `sapient_state` | | detection | state |
| `position_accuracy_h_m` | m | detection, alert | range error of a geolocated range and bearing |
| `sapient_system` | | status | `OK`, `WARNING`, `ERROR`, `GOODBYE` |
| `sapient_mode` | | status | mode |
| `sapient_power_level` | % | status | power level, 0 to 100 |
| `sapient_node_type` | | status, registration | node type from the registration |
| `update_interval_s` | s | registration | status interval |
| `sapient_alert_type` | | alert | e.g. `WARNING`, `CRITICAL`, `MODE_CHANGE` |
| `sapient_alert_status` | | alert | e.g. `ACTIVE`, `CLEAR` |
| `sapient_priority` | | alert | `LOW`, `MEDIUM`, `HIGH` |
| `sapient_ranking` | 0 to 1 | alert | ranking |
| `hostility` | | all | only when `default_hostility` is set |

A value outside its range (confidence, power level, ranking) is not emitted.
A detection's or alert's confidence in 0 to 1 becomes the event's
`confidence`. When an event's entity type is a MIM type, which does not
declare these names, each one goes to metadata under the same key.

Metadata keys:

| Message | Keys |
|---|---|
| all | `node_id`, `sapient_version` (`BSI Flex 335 v2.0`), `source_uid` |
| detection | `object_id`, `report_id`, `task_id`, `native_id`, `colour`, `classification_<i>` (other classifications), `info_<type>` (track and object info), `signal_<i>_centre_frequency`, `signal_<i>_amplitude`, `file_<i>_url`, `velocity_units` (`km/h` when the node declared it), `node_name` |
| status | `report_id`, `power_source`, `power_status`, `active_task_id`, `status_<type>` (`<level>: <value>`), `node_name` |
| registration | `sapient_message` (`registration`), `node_name`, `node_short_name`, `icd_version`, `node_sub_type`, `capability_<i>`, `manufacturer`, `model`, `serial_number` |
| alert | `alert_id`, `description`, `region_id` |
| positions | `altitude_known` (`false` when the position has no altitude); `<prefix>_x_error`, `<prefix>_y_error` (position error, in the coordinate's units); for a position that is not latitude and longitude: `<prefix>_x`, `_y`, `_z`, `_utm_zone`, `_coordinate_system`. The prefix is `location` for a detection or alert and `node` for a status report. |
| range and bearing | `bearing_deg`, `range_m`, and `unlocated_reason` when no position was derived |

## Configuration

Start from [`sapient.example.toml`](sapient.example.toml).
`ajar-sapient --profile ./sapient.toml` prints the profile the operator
registers.

`[options]`, unknown keys refused:

| Key | Default | Meaning |
|---|---|---|
| `role` | `dmm` | `dmm` or `subscriber` |
| `node_id` | a fresh UUID each start | this fusion node's id in every registration acknowledgement |
| `types.detection` | `sapient:detection` | entity type of a detection report without track information |
| `types.track` | `sapient:track` | entity type of a detection report with track information |
| `types.sensor_status` | `sapient:sensor-status` | entity type of status reports and registrations |
| `types.alert` | `sapient:alert` | entity type of alerts |

Each type must be namespaced (contain `:`), or the config is refused.

Shared keys the connector uses:

- `[entity_map]`: SAPIENT classification (case-insensitive) to entity type,
  for example `"UAV" = "mim:aircraft"`. It applies to detection reports, on
  the top classification, and wins over `[options.types]`.
- `default_hostility`: SAPIENT carries no hostility; this sets one on every
  event.
- `[marking]`: the security marking stamped on every event.

**Entity types.** The `sapient:` types are not in the vendored MIM ontology.
They are an operator-registered fragment, [`sapient.types.json`](sapient.types.json),
parented to `mim:object`, `mim:sensor` and `mim:action`. The Core operator
registers it with the first invite:

```sh
ajar invite sapient-fusion-1 --connector sapient --entities sapient: \
  --entity-file sapient.types.json
```

A site that has not registered the fragment sets `[options.types]` to MIM
types, for example `track = "mim:aircraft"` and `sensor_status = "mim:sensor"`.
The SAPIENT-specific attributes then go to metadata.

## Behaviour

**Registration in the `dmm` role.** A sensor sends a `Registration` first and
reports nothing until acknowledged. The connector accepts every registration:
it replies with a `RegistrationAck` (acceptance true) from `node_id` to the
sensor's node id, then forwards the registration to the parser like any other
message. Acknowledgements are counted in `sapient_acknowledged_total`. A frame
whose prefix declares more than 64 KiB closes that connection and counts in
`sapient_bad_framing_total`. Messages wait in a 1024-frame queue; when it is
full, reading from the sensors pauses.

**Per-node state.** From each node's registration the connector keeps its
name, node type and velocity units; from its status reports, its last
position. It holds this in memory for up to 4096 nodes. The state starts empty
on every restart and in a subscriber that joins mid-stream.

**Velocity units.** SAPIENT velocities are ENU vectors in the units the node
declared at registration, m/s or km/h. km/h is converted to m/s. A node not
seen registering is read as m/s. `speed` and `course` need both east and
north rates.

**Positions.** A latitude-longitude position, in degrees or radians, becomes
the event location in WGS-84 degrees and metres; a missing altitude is 0 with
`altitude_known = false`. A UTM position, or one outside the globe, gives no
location and goes to metadata.

**Range and bearing.** A report given as range and bearing is placed from the
node's last reported position on a sphere of mean Earth radius, accurate to
within a metre at counter-UAS ranges. Elevation, when present, splits the
range into horizontal distance and height above the node. The event has no
location, carries `unlocated_reason`, and counts in `sapient_unlocated_total`
when:

- the bearing datum is not true north (`bearing datum is not true north`);
- the node has not yet reported its position (`node position not yet reported`);
- range or bearing is missing, or the units are unspecified (`range or bearing missing`).

Metrics on `/metrics` when `AJAR_HEALTH_ADDR` is set:
`sapient_unmapped_total`, `sapient_unlocated_total`,
`sapient_registrations_total`, and in the `dmm` role
`sapient_acknowledged_total` and `sapient_bad_framing_total`.

## Limits

- Only BSI Flex 335 v2.0 is decoded. The wire crate can compile the v1.0
  schema behind its `v1` feature, but this connector does not read it.
- The connector never tasks a node and never acknowledges alerts.
- UTM positions are not converted.

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

The connector reads the file from the start, then keeps following it for
appends. `tests/data/sapient-capture.bin` is a bench scenario in this form: a
radar registers, reports its position, follows a UAV closing from the
north-east over five reports, and raises an alert.

## Conformance

`cargo test -p ajar-sapient` checks that a detection decodes to one located
event in the contract's units, that the message is sealed verbatim in the
payload, that the seal verifies under the published contract key, that the
bench capture replays through the `file` transport with every message
published, that a registration is acknowledged, and that mutated real
messages and random bytes never panic.
