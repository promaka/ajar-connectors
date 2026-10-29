<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-generic

Config-driven ingress connector for simple sources that emit JSON objects or
delimited rows. A `[mapping]` block in the connector's TOML says which record
fields become the timestamp, location, confidence, attributes and metadata, and
the connector publishes each record to Core as a signed event. No Rust is
needed. A source that needs real parsing (a binary frame, reassembly, a wire
standard) needs a hand-written connector, such as [tak-cot](../tak-cot) or
[ais-nmea](../ais-nmea), or the code path in
[`connector-template`](../../examples/connector-template).

## Input

One record per frame: a JSON object (`format = "json"`) or one delimited row
(`format = "csv"`). The transport's framing decides where a record ends, so
any transport works; stream transports usually take `framing = "line"`.

A frame is rejected with a typed error when it is not UTF-8, is not valid JSON
or not a JSON object, lacks the mapped timestamp field, or has a lat, lon, alt,
confidence or epoch timestamp value that is not a number.

JSON values are read as text: strings unquoted, numbers and booleans as
written, `null` as an empty string, a nested object or array as its JSON text.
Only top-level keys can be mapped.

CSV rows are split on `delimiter` with no quoting or escaping. Each value is
trimmed and named by its position in `columns`. A row with fewer values than
`columns` leaves the last columns absent; extra values are ignored.

## Output

Every event has the mapping's `entity_type`, a fresh UUIDv7 id, and the frame
as it arrived in its payload.

| Event field | From |
|---|---|
| timestamp | `timestamp_field`, converted by `timestamp_format`; the time of receipt when unset |
| location | `lat_field`, `lon_field` in degrees and `alt_field` in metres, only when both lat and lon are present in the record |
| confidence | `confidence_field`: a value above 1 is read as a percentage (87 becomes 0.87), then clamped to 0 to 1; 0 when unset or absent |
| attributes | each `[mapping.attributes]` entry whose record field is present, plus `hostility` from `default_hostility` |
| metadata | each `[mapping.metadata]` entry whose record field is present |

Values pass through as text with no unit conversion. A mapped attribute must
already be in the unit the ontology declares for it.

Identity: map the feed's native id to the `source_uid` metadata key, so Core
keeps each object its own track. A governed identity is set by mapping fields
to the `alt_id` and `alt_id_standard` attributes where the entity type declares
them. Without a `source_uid`, every event of the connector shares one track.

## Configuration

The connector config and the `[mapping]` block share one file. Three examples:

| File | Source |
|---|---|
| [`generic.example.toml`](generic.example.toml) | Newline JSON sensor records, with a CSV variant |
| [`camera-detections.example.toml`](camera-detections.example.toml) | EO/IR camera detections: geolocated `mim:object`, `confidence_field`, `track_id` as `source_uid` |
| [`esm-synthetic.example.toml`](esm-synthetic.example.toml) | ESM intercepts from a receiver or `ajar-feed-synthetic esm`: bearing-only `mim:equipment`, no location |

`[mapping]` keys:

| Key | Default | Meaning |
|---|---|---|
| `format` | required | `json` or `csv` |
| `columns` | none | CSV column names in order; required for `csv` |
| `delimiter` | `","` | CSV delimiter |
| `entity_type` | required | Entity type of every event |
| `timestamp_field` | none | Record field with the observation time |
| `timestamp_format` | `rfc3339` | `rfc3339` (used as is), `epoch-millis` or `epoch-seconds` |
| `lat_field`, `lon_field` | none | Record fields with WGS-84 degrees |
| `alt_field` | none | Record field with altitude in metres |
| `confidence_field` | none | Record field with a detection or track confidence |
| `[mapping.attributes]` | empty | `record_field = "attribute_key"` |
| `[mapping.metadata]` | empty | `record_field = "metadata_key"` |

`default_hostility` (default none) adds a `hostility` attribute to every event.

```bash
ajar-generic ./generic.toml
ajar-generic ./generic.toml --profile   # print the profile to register, then exit
```

## Behaviour

### Ontology check at startup

The connector refuses to start when the mapping
names an entity type the vendored ontology does not declare, an attribute key
the entity type does not declare, or a `default_hostility` outside the
`hostility` vocabulary. Core would reject such events or quarantine the fields.
The log names each fault and the closest valid name. An `x:<vendor>:<type>`
entity type skips the check and must be registered with Core first.

### Attribute or metadata

Put governed fields in `[mapping.attributes]`.
Native ids, vendor vocabulary and anything the ontology does not govern go in
`[mapping.metadata]`. A record's confidence goes in `confidence_field`; as an
attribute it would be quarantined.

### Unmapped fields

A record field not named in the mapping is not decoded,
but it stays in the payload.

## Limits

- Only top-level JSON keys; no nested paths.
- No CSV quoting, header row detection or escaping.
- No per-field transforms other than the epoch to RFC 3339 timestamp
  conversion and the confidence percentage.
- One record per frame.

## Conformance

`cargo test` checks that events meet Core's content contract (UUIDv7 id,
RFC 3339 timestamp, sorted attributes and metadata), that a native id rides in
metadata and never as the event id, and that the seal verifies under the
published contract key. Every `*.example.toml` in the workspace is checked to
parse, and each generic example to pass the startup ontology check. Property
tests run 4096 cases each of arbitrary bytes (through a JSON and a CSV mapping)
and JSON-shaped input and assert the parser never panics.
