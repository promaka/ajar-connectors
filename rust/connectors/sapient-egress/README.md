<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-sapient-egress: Ajar as a SAPIENT sensor node

Egress connector for **SAPIENT** (BSI Flex 335). Ajar registers with a
fusion node as one more sensor node and sends it governed events as
detection reports. Feeds the fusion node has no SAPIENT sensor for, such as
MAVLink, ADS-B, AIS or ASTERIX, then reach it as tracks from a node called
Ajar.

```
NATS ajar.egress.signed.> ──▶ ajar-sapient-egress ──TCP──▶ fusion node
  (sealed by Core)          verify + map + register      (sees a SAPIENT node)
```

## Input

The connector subscribes to `subject` on Ajar's NATS, by default the signed
egress channel `ajar.egress.signed.>`. There Core publishes each event its
policy released, sealed under the egress key. A subject outside
`ajar.egress.` is refused at load. The rendering subjects (`cot`, `geojson`)
carry plain renderings and do not verify.

Each envelope is verified under Core's egress key and decoded:

| Case | Handling | Counter |
|---|---|---|
| fails to verify or decode | dropped, logged | `egress_rejected_total` |
| event id seen in the last 10 000 | dropped | `egress_deduped_total` |
| no location | dropped | `egress_unlocated_total` |
| otherwise | one detection report | `egress_delivered_total` once written |

## Output

BSI Flex 335 v2.0 protobuf over TCP to `fusion_node`, each message framed by
a 4-byte little-endian length prefix.

| When | Message |
|---|---|
| on every connection | a `Registration` (below). Nothing else is sent until the fusion node acknowledges it. |
| every `status_interval_s` while registered | a `StatusReport`: system `OK`, mode `Default`, info `NEW` on the first after a registration and `UNCHANGED` after, and the configured `location` if any |
| per accepted event | a `DetectionReport` (below) |
| on a `Task` from the fusion node | a `TaskAck` with status `REJECTED`, addressed to the sender. The node relays governed events and takes no tasks. |

An `Error` from the fusion node is logged. Other inbound messages are ignored.

The registration states:

- node type `OTHER`, sub-type `Ajar governed relay`, ICD version `BSI Flex 335 v2.0`;
- `name` and `short_name`;
- one capability: category `Fusion`, type `Governed track relay`, value `Ajar`;
- the status interval in seconds, with WGS-84 latitude-longitude positions;
- one permanent mode, `Default`, with settle time 0, whose detection
  definition declares WGS-84 latitude-longitude in degrees and metres, ENU
  velocity in m/s, a `detection_confidence` from 0 to 1 and single-class
  confidence;
- a task definition with zero concurrent tasks;
- manufacturer `Ajar`, model `ajar-sapient-egress`, and the connector version.

Detection report mapping:

| SAPIENT field | From the Ajar event |
|---|---|
| `location` | event location: WGS-84 `LAT_LNG_DEG_M`, x longitude, y latitude, z altitude in metres |
| `enu_velocity` | east `speed·sin(course)`, north `speed·cos(course)`, up `vertical_rate`, in m/s. Sent only when `speed` (non-negative) and `course` are both numeric attributes. |
| `classification` | `sapient_classification` attribute, else `object_class` attribute, else the entity type's classification (below), else `default_classification` |
| classification `confidence` | `sapient_classification_confidence` attribute, when in 0 to 1 |
| `detection_confidence` | event confidence, when above 0 and at most 1 |
| `id` | `source_uid` metadata, else the event id |
| `object_id` | a ULID per `<source_id>:<source_uid>` (below) |
| `report_id` | a fresh ULID |
| `object_info` | `Ajar Source` (source id), `Ajar Event` (event id), `Ajar Type` (entity type), and `Hostility` when the event has a `hostility` attribute |
| envelope timestamp | event timestamp, else the send time |

The event's security marking is not carried.

Built-in classification per entity type:

| Entity type | Classification |
|---|---|
| `mim:aircraft` | `Aircraft` |
| `mim:vessel`, `mim:surface-vessel` | `Vessel` |
| `mim:subsurface-vessel` | `Submarine` |
| `mim:land-vehicle` | `Vehicle` |
| `mim:person` | `Person` |
| `mim:unit` | `Unit` |
| `mim:facility` | `Facility` |
| `mim:weapon` | `Weapon` |
| `mim:sensor` | `Sensor` |
| `mim:object` | `Unknown` |

The match is on the exact entity type, not its parents.

## Configuration

Start from [`sapient-egress.example.toml`](sapient-egress.example.toml) and
run `ajar-sapient-egress ./sapient-egress.toml` (the default path). Unknown
keys are refused.

| Key | Default | Meaning |
|---|---|---|
| `nats_url` | required | `tls://<host>:443` in production, with `AJAR_TLS_CA`, `AJAR_TLS_CERT` and `AJAR_TLS_KEY` set to the subscribe-only certificate |
| `subject` | `ajar.egress.signed.>` | must start with `ajar.egress.`; narrow with `ajar.egress.signed.<source_id>` |
| `egress_verifying_key` | required | Core's egress key: 64 hex characters, or a path to a file holding them |
| `[sapient] fusion_node` | required | `host:port` |
| `[sapient] node_id` | a fresh UUID each start | set it so a restart re-registers as the same node |
| `[sapient] name` | `Ajar` | node name |
| `[sapient] short_name` | `AJAR` | node short name |
| `[sapient] status_interval_s` | `5.0` | seconds between status reports, declared at registration; must be positive |
| `[sapient] buffer_max` | `1000` | reports held while the fusion node is unreachable; at least 1 |
| `[sapient] default_classification` | `Unknown` | classification for an entity type nothing else names |
| `[sapient.location]` | none | `lat`, `lon`, `alt_m` (default 0): this node's position in status reports |
| `[sapient.classification]` | empty | entity type to classification, over the built-in table |

**Onboarding.** The operator issues a consumer identity with a subscribe-only
certificate, as for the TAK egress:

```sh
ajar onboard sapient-out-1 --consumer --egress-scope signed ...
```

The packet's `egress_verifying_key_hex` and `nats_url` go into the config.
Core publishes the signed channel from release 0.1.28.

## Behaviour

**Link.** The connector connects to the fusion node (5 s timeout), sends the
registration and waits up to 10 s for the acknowledgement. A rejection is
logged with the fusion node's reasons and counted in
`egress_sapient_registrations_rejected_total`. Any connect, write or read
error drops the connection; the connector retries about every second and
re-registers each time. Reconnections are counted in
`egress_sapient_reconnects_total`, and `egress_sapient_link_up` is 1 while
registered.

**Buffer.** Detection reports wait in a queue of up to `buffer_max` and are
sent oldest first. While the link is down the queue holds them; when it is
full the oldest is dropped and counted in `egress_gap_dropped_total`. Status
reports are not queued: while the link is down none is sent. On shutdown the
connector spends up to 2 s sending what is queued.

**Track identity.** Each `<source_id>:<source_uid>` gets one SAPIENT object
id, so the fusion node sees a track rather than separate detections. The
connector remembers 10 000 of them in memory; beyond that the oldest is
forgotten and its next report starts a new track. A restart also starts new
tracks.

Metrics on `/metrics` when `AJAR_HEALTH_ADDR` is set:
`egress_delivered_total`, `egress_rejected_total`, `egress_deduped_total`,
`egress_unlocated_total`, `egress_gap_dropped_total`,
`egress_sapient_status_sent_total`, `egress_sapient_tasks_refused_total`,
`egress_sapient_reconnects_total`,
`egress_sapient_registrations_rejected_total` and `egress_sapient_link_up`.

## Limits

- Only BSI Flex 335 v2.0 is sent.
- Events without a location are not sent.
- Tasks are always refused; the node cannot be pointed, moved or
  re-thresholded.
- A fusion node product may require particular capability strings or a node
  type. These are set in one place, `Node::registration` in `src/report.rs`,
  and a refusal's reasons are logged.

## Conformance

`cargo test -p ajar-sapient-egress` checks that a governed event becomes a
located, classified detection report with stable object ids and m/s
velocity, that the registration carries every mandatory field and survives
the wire, that a fusion node's rejection is reported with its reasons, that
a dropped connection re-registers on the next send, that a task is refused,
and that the buffer drops the oldest report and counts it.
