<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-tak-cot

Ingress connector for **Cursor-on-Target (CoT)**, the situational-awareness XML
that ATAK, WinTAK and TAK-aware sensors broadcast. Each CoT `<event>` becomes one
canonical Ajar event, sealed with the connector's Ed25519 key and published to
`<subject_prefix>.<source_id>` on Core's NATS. Nothing on the TAK side changes.
See [HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md) for the seal and ingest path.

## Input

One CoT `<event>` per frame, parsed with an XML reader. The connector reads:

| Element | Fields |
|---------|--------|
| `<event>` | `uid`, `type`, `time` (all three required) |
| `<point>` | `lat`, `lon`, `hae` |
| `<detail><contact>` | `callsign` |
| `<detail><track>` | `course`, `speed` |
| `<confidence>` | `value` attribute or element text (not standard CoT) |

Every other element and attribute (`start`, `stale`, `ce`, `le`, `remarks`, ...)
is not decoded and stays in the payload.

The SA default transport is `udp-multicast` (ATAK and WinTAK use group
`239.2.3.1`, port `6969`) or `udp`. One datagram is one frame. Any transport that
delivers one `<event>` per frame works.

## Output

**Entity type**, in this order:

1. an exact match of the CoT `type` in `[entity_map]`;
2. the battle dimension (third `type` field): `A` → `mim:aircraft`,
   `S` → `mim:vessel`, `U` → `mim:subsurface-vessel`;
3. otherwise `x:cot:<type>` with `-` replaced by `_` (`a-f-G-U-C` →
   `x:cot:a_f_G_U_C`).

No track is dropped for lack of a mapping. What Core accepts is set by the
site's ontology and the entity-type prefixes registered for the connector.

**Identity.** The event `id` is a fresh UUIDv7. The CoT `uid` is the
`source_uid` metadata key and the governed identity: `alt_id` = the uid,
`alt_id_standard` = `CoT`. A uid longer than 128 bytes sets no `alt_id`.

| Attribute | Unit | From |
|-----------|------|------|
| `hostility` | MIM `HostilityCodeType` | second `type` field, always set (table below) |
| `callsign` | text | `<contact callsign>` |
| `course` | degrees from true north, 1 decimal | `<track course>` |
| `speed` | m/s, 2 decimals | `<track speed>` |
| `alt_id`, `alt_id_standard` | text | `uid`, `CoT` |

CoT already states course in degrees from true north and speed in m/s, so
neither is converted.

| CoT | `hostility` | CoT | `hostility` |
|-----|-------------|-----|-------------|
| `f` | `Friend` | `p` | `Pending` |
| `a` | `AssumedFriend` | `j` | `Joker` |
| `h` | `Hostile` | `k` | `Faker` |
| `s` | `Suspect` | anything else, or absent | `Unknown` |
| `n` | `Neutral` | | |

`j` and `k` are the exercise codes and are passed through as such, so an
exercise track does not reach a picture as a real threat. The values are
case-sensitive MIM 5.3 terms. A site whose ontology does not govern
`hostility` quarantines it into metadata (graceful) or rejects the event
(strict).

**Location**: `lat`/`lon` in WGS-84 degrees and `hae` in metres. **Timestamp**:
the event `time`, which must be RFC 3339. **Confidence**: from `<confidence>`,
see Behaviour; 0 when absent.

**Metadata**: `source_uid` (the CoT uid).

**Payload**: the CoT frame, byte for byte.

The attribute reference for all connectors is
[ATTRIBUTES.md](../ATTRIBUTES.md).

## Configuration

Start from [`tak-cot.example.toml`](tak-cot.example.toml). The connector has no
`[options]`. It uses the shared keys (`source_id`, `nats_url`, `subject_prefix`,
`signing_key_path`, `[transport]`, `[marking]`, `spool`) and:

| Key | Default | Meaning |
|-----|---------|---------|
| `[entity_map]` | empty | CoT `type` → Ajar entity type, exact match, checked before the battle-dimension default |

`ajar-tak-cot <config> --profile` prints the profile the operator registers in
Core and exits. Its allowed entity types are `mim:`, `x:cot:` and any
`[entity_map]` target outside those prefixes.

## Behaviour

- A frame is rejected, counted in `connector_rejected_total` and logged when it
  is not well-formed XML, has no `<event>`, lacks `uid`, `type` or `time`, has a
  non-numeric `lat` or `lon`, or fails to build (a `time` that is not RFC 3339,
  a coordinate out of range).
- A `<point>` with both `lat` and `lon` sets the location. Without either, the
  event has no location.
- A `course` or `speed` that is empty, not a number or not finite is skipped and
  the track kept. A course outside 0 to 360 and a negative speed are skipped.
  No `<track>` sets neither attribute.
- Confidence comes from `<confidence value="..."/>` or
  `<confidence>...</confidence>`; the attribute wins if both are present. A
  value above 1 is read as a percentage (`87` → 0.87); the result is clamped to
  0 to 1.

## Limits

- One event per frame. A TAK server's TCP stream of concatenated `<event>`s
  without a delimiter is not split.
- `start`, `stale`, `how`, `ce`, `le`, remarks and other `<detail>` children are
  not decoded.

## Run

```bash
ajar-tak-cot ./tak-cot.toml
```

For production, `AJAR_TLS_CA`, `AJAR_TLS_CERT` and `AJAR_TLS_KEY` give the mTLS
client identity (CN = `source_id`), and `AJAR_HEALTH_ADDR` serves `/healthz` and
`/metrics`. `RUST_LOG=debug` raises log detail. Core must hold the public half of
the signing key against `source_id`; see [SECURITY.md](../../../SECURITY.md).

## Conformance

`cargo test -p ajar-tak-cot` runs, beside the unit tests:

- the event meets Core's content contract (UUIDv7 id, RFC 3339 timestamp,
  sorted unique attributes and metadata);
- the uid is `source_uid` metadata, not the id;
- a seal with the contract test seed verifies under the published key;
- a fuzz test over arbitrary and CoT-shaped input asserts the parser never
  panics.
