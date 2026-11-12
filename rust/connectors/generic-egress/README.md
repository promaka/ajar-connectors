<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-generic-egress

Egress connector from Ajar Core to an HTTP endpoint. It subscribes to governed
events on NATS, verifies Core's egress signature, renders each event as one JSON
object in the consumer's field names, and POSTs it. It is the egress counterpart
of [`ajar-generic`](../generic): a mapping, no code.

```
Core ──▶ ajar.egress.<format>.<source> ──▶ verify egress signature ──▶ map ──▶ HTTP POST
```

## Input

NATS subject `egress_subject`, which must start with `ajar.egress.`. Any other subject
is refused at startup. This prefix rule keeps the effector cue channel
(`ajar.cue.>`) out of reach of the connector. The NATS connection uses the
`AJAR_TLS_CA`, `AJAR_TLS_CERT` and `AJAR_TLS_KEY` environment; the consumer's
subscribe-only certificate decides what it can see under the prefix.

Each message is a sealed envelope. It is verified under Core's egress key
(the `egress_verifying_key` file, which the invite carries) and decoded as an
Ajar event. An envelope that fails verification or decoding is logged, counted
as rejected and not delivered. Verification cannot be turned off.

Producer signatures do not reach the consumer. Core re-signs at egress because
the payload is dropped on egress and identity may be dropped across coalitions,
so the producer's signature would cover bytes that no longer exist. Provenance
at the consumer is Core's egress signature. Full lineage to the original sealed
envelope is in Ajar's audit chain.

## Output

One HTTP POST per event, with one JSON object as body, to `target`. A 2xx
response is a delivery. The object holds:

- each `[mapping]` field, `consumer_name = "path"`. A path absent from the event
  is left out of the object, not sent as null.
- the event id as `event_id` and the policy tags as `policy_tags`, unless the
  mapping names the `id` or `policy_tags` path, in which case they appear only
  under the mapping's names. A mapping can rename them but not remove them.
- `governance`: `{"egress_signature": "verified"}`, set by verification.
- `unmapped`, when `unmapped = "include"`: every attribute and metadata entry the
  mapping does not name, as `{"attributes": {...}, "metadata": {...}}`.
- `confidentiality_label`, when configured and the event has a `class:` tag.

The names `event_id`, `policy_tags`, `governance`, `unmapped` and
`confidentiality_label` overwrite a mapping field of the same name.

Mapping paths:

| Path | JSON value |
|------|------------|
| `id`, `source_id`, `entity_type`, `timestamp` | string |
| `lat`, `lon` | number, WGS-84 degrees; absent without a location |
| `alt_m` | number, metres; absent without a location |
| `confidence` | number, 0 to 1 |
| `policy_tags` | array of strings |
| `attr:<name>` | string, the governed attribute's value in its declared unit |
| `meta:<name>` | string, the metadata value (`meta:source_uid` is the native track id) |

The event payload is never delivered. Core fields the mapping does not name
(location, timestamp, source, entity type, confidence) are left out; only
attributes and metadata fall under `unmapped`.

**Confidentiality label.** With `[confidentiality_label]` set, the object gets a
STANAG 4774-shaped label projected from the policy tags. It changes no
enforcement, and `policy_tags` is still delivered as the source of truth. The
label is bound to the data by the signature, because it is derived from policy
tags inside the sealed envelope.

| Label field | From |
|-------------|------|
| `policyIdentifier` | `policy_identifier` from config |
| `classification` | the first non-empty `class:` tag, uppercased; no such tag means no label |
| `categories` | one `Releasability` category, `PERMISSIVE`, from all `rel:` and `releasable:` tags, uppercased, sorted, deduplicated; left out when there are none |
| `creationDateTime` | the event timestamp |

Values are not reinterpreted: the deployment's policy owns the vocabulary.

## Configuration

`ajar-connectors join` writes the config: the first four keys come from the
invite and from `join --target`, and the rest from the instance's
`settings.toml`. To run the connector by hand, start from
[`generic-egress.example.toml`](generic-egress.example.toml).

| Key | Default | Meaning |
|-----|---------|---------|
| `nats_url` | required | Ajar NATS, `tls://` in production |
| `egress_subject` | required | under `ajar.egress.`, wildcards allowed |
| `egress_verifying_key` | required | a file holding Core's egress key as 64 hex characters |
| `target` | required | endpoint for the POSTs |
| `[deliver] headers` | none | extra request headers, such as the consumer's bearer token |
| `[deliver] attempts` | `2` | attempts per event, at least 1 |
| `[mapping]` | required, non-empty | consumer field name = path; an unknown path is refused at startup |
| `unmapped` | `include` | `include` or `refuse` |
| `[confidentiality_label] policy_identifier` | none (no label) | the security policy the label's values are defined by |

Unknown keys are refused, except inside `[mapping]`, where every key is a
consumer field name.

## Behaviour

- Delivery is inline and in order: the next NATS message waits until the current
  event is delivered or given up. Each POST times out after 10 s. After a failed
  attempt (an error or a non-2xx status) the connector waits 500 ms times the
  attempt number before the next. An event that fails every attempt is dropped.
  Delivery is at-most-once; nothing is buffered or kept across a restart.
- The last 4096 event ids are remembered, and an event whose id was seen is
  skipped.
- With `unmapped = "refuse"`, an event carrying any attribute or metadata the
  mapping does not name is not delivered.
- Every 15 s a heartbeat log line reports `received`, `delivered`, `rejected`
  (verification or decoding failed), `deduped` and `gap_dropped` (refused by
  `unmapped = "refuse"`, or not delivered within the attempts).

Make the endpoint idempotent on the event id.

## Limits

- At-most-once only; no durable (JetStream) consumer.
- HTTP POST of JSON is the only output.

## Run

```bash
ajar-generic-egress ./generic-egress.toml
ajar-generic-egress --dry-run ./generic-egress.toml
```

`--dry-run` connects and verifies as usual, then prints each mapped object to
stdout instead of POSTing. If the egress key cannot be loaded, a dry run prints
only `UNVERIFIED payload: <n> bytes on <subject>` per message and maps nothing.
