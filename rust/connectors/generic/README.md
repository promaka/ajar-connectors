<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-generic

The **no-code** ingress connector. For the long tail of simple sources that emit
JSON or CSV, you do not write Rust — you write a field mapping in the connector's
TOML, and this binary turns each record into a sealed, canonical Ajar event.

It is the config-driven sibling of the [`connector-template`](../../examples/connector-template)
(which is the *little-code* path for sources that need real parsing logic). Both
run on the same shared runtime and any transport.

## When to use which

| Your source… | Use |
|--------------|-----|
| emits JSON objects or delimited rows, flat fields | **ajar-generic** (this — a mapping, no code) |
| needs real parsing (binary frame, reassembly, a wire standard) | a hand-written connector ([tak-cot](../tak-cot), [ais-nmea](../ais-nmea), …) or the code template |

## Configure

Everything is one TOML file: the usual connector config (identity, transport,
key) plus a `[mapping]` block. See [`generic.example.toml`](generic.example.toml).

```toml
[transport]              # any method: udp / tcp / http-server / file / exec / stdin / serial / mqtt / rest-poll
kind = "tcp-client"
connect = "gateway:9000"

[mapping]
format = "json"                    # or "csv" (with columns = [...])
entity_type = "x:acme:sensor"      # must be registered in the ontology
timestamp_field = "observed_at"    # omit to stamp receipt time
timestamp_format = "rfc3339"       # rfc3339 | epoch-millis | epoch-seconds
lat_field = "latitude"             # a location is emitted only if lat AND lon map
lon_field = "longitude"
alt_field = "altitude_m"           # optional
[mapping.attributes]               # governed (ontology-validated): source = ajar_key
speed = "speed"
[mapping.metadata]                 # ungoverned passthrough: source = metadata_key
sensor_id = "sensor_id"            # native ids go here — never the event id
```

The event id is always a fresh UUIDv7; native identifiers go in `metadata`, exactly
as the hand-written connectors do — so Core accepts these events under the same
content contract.

## Run

```bash
ajar-generic ./generic.toml
# production mTLS + health as per the connectors README
```

## Limits (when to graduate to code)

- Flat fields only — no nested JSON paths.
- One record per frame (the transport's framing decides record boundaries).
- No per-field transforms beyond timestamp epoch→RFC 3339.

Anything past these is a few lines in the code template, not a config change.

## Conformance

`cargo test` proves the same contract as every connector: content-validity
(UUIDv7 id + RFC 3339 timestamp), native id in `metadata` (not `attributes`, not
the id), canonical ordering, the seal verifies under the published contract key,
and a fuzz pass (arbitrary and JSON/CSV-shaped input never panics).
