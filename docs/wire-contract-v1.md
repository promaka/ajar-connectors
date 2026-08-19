<!-- SPDX-License-Identifier: Apache-2.0 -->
# Ajar wire contract, `contract-v1`

Everything an implementation must agree with to produce events Ajar accepts: the
event shape, the bytes that get signed, the seal, the subject, the attribute
vocabulary, and what is frozen versus what may change under you.

Read this before choosing an SDK. It is the whole agreement; nothing else in this
repository adds a requirement, and no part of it depends on Ajar Core being
present or licensed. An implementation that satisfies this document and passes
the conformance vectors is conformant, whoever wrote it.

**Status:** `contract-v1`, stamped in [`vendor/contract/CONTRACT_VERSION`](../vendor/contract/CONTRACT_VERSION).

---

## 1. The event

The full schema is [`vendor/contract/event.proto`](../vendor/contract/event.proto),
package `ajar.event.v1`. Vendored, hash-pinned, and checked on every build by
`scripts/check-contract.sh`.

```proto
message Event {
  string   schema_version = 1;
  string   id             = 2;   // UUIDv7
  string   source_id      = 3;   // your registered identity
  string   entity_type    = 4;   // ontology class, e.g. "mim:aircraft"
  string   timestamp      = 5;   // RFC 3339
  GeoPoint location       = 6;
  bytes    payload        = 7;   // your source frame, verbatim
  repeated string policy_tags = 8;
  double   confidence     = 9;
  string   received_at    = 10;
  repeated Attribute attributes = 11;   // governed by the ontology
  repeated Attribute metadata   = 12;   // ungoverned passthrough
}
```

Four rules the wire format does not express but Ajar enforces:

| Field | Requirement |
|---|---|
| `id` | UUIDv7. Fresh per event — never your source's native identifier |
| `timestamp` | RFC 3339 |
| `attributes` | Sorted by `key`, keys unique. See §2 |
| `source_id` | Must match the identity the signing key is registered against |

A native identifier (ICAO address, MMSI, track number) belongs in `metadata`,
never in `id` and never in `attributes`.

## 2. Canonical bytes

The canonical bytes are the protobuf encoding of `Event`. They are what you sign
and what Ajar hashes.

**Protobuf serialization is not canonical in general.** The specification does
not require a field order, and implementations differ. The five SDKs here use
five different encoders — prost, Go protobuf, libprotobuf, nanopb, Python
protobuf — so byte-identity between them is an empirical property that is tested,
not a guarantee inherited from protobuf.

Three things hold it together:

1. The contract declares **no map fields** — the one proto construct with
   unspecified ordering.
2. The caller supplies `attributes` **sorted by key, with unique keys**. This is
   the one rule an implementation can violate on its own; a non-canonical
   ordering is rejected.
3. The **golden vectors** confirm every encoder still agrees.

If you are writing a sixth implementation, treat
[`vendor/contract/vectors.json`](../vendor/contract/vectors.json) as the
specification rather than assuming your protobuf library agrees with ours. Each
vector pairs a fixture in [`vendor/contract/corpus/`](../vendor/contract/corpus/)
with the exact canonical bytes and their SHA-256.

Verify with `ajar-conformance` (see §6) — no network, no Core.

## 3. The seal

```text
sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
         └───────────── 64-byte detached signature ─────────────┘
```

Split at 64 bytes: the prefix is the signature, the remainder is the canonical
event. A verifier holding the publisher's registered public key can establish
provenance with neither the connector, the broker, nor Ajar Core present.

The envelope is **bare** — no algorithm identifier, no key identifier, no signing
time. The algorithm is fixed by this contract version; the key is identified by
`source_id`; the time is the event's own `timestamp`. This is frozen for `v1`
(§7).

Signature algorithm: **Ed25519** (RFC 8032), 32-byte seed, 32-byte public key.

> **Procurement note.** Ed25519 is absent from BSI TR-02102-1, SOG-IS 1.3 and
> ECCG 2.0. If your accreditation requires an approved-list signature scheme,
> raise it before you build — see [COMPATIBILITY.md](../COMPATIBILITY.md#cryptographic-lifecycle)
> for how algorithm changes are handled without breaking the wire format.

## 4. Publishing

Sealed events are published to NATS:

```
ajar.ingest.<source_id>
```

One subject per registered identity. The subject scheme is frozen for `v1`.

Transport security is mTLS in production; the client certificate CN is the
`source_id`. The connector holds no Ajar secrets — only its own signing key.

## 5. Attributes and the ontology

`entity_type` and `attributes` are governed by Ajar's ontology. `metadata` is not
governed and is always accepted.

**The failure mode to understand before you build:** Ajar runs a graceful mode.
An unrecognised `entity_type`, attribute name, or controlled-vocabulary value is
**discarded without an error**. Your connector runs, seals events, publishes
successfully — and the data does not arrive. Nothing fails loudly.

Consequences:

- Agree `entity_type` and attribute names with your operator **before** writing
  the mapping.
- Controlled vocabularies are **case-sensitive**. `hostility` takes MIM 5.3
  `HostilityCodeType`: `Friend`, `AssumedFriend`, `Hostile`, `AssumedHostile`,
  `Suspect`, `Neutral`, `AssumedNeutral`, `Involved`, `AssumedInvolved`,
  `Pending`, `Unknown`, `Faker`, `Joker`. Lower-case `friendly` is silently lost.
- Units are yours to normalise. Governed `speed` is m/s, `vertical_rate` m/s,
  `course` degrees. Keep the native units in `metadata`.

Full reference: [ATTRIBUTES.md](../rust/connectors/ATTRIBUTES.md).

> The machine-readable ontology (`ontology.json`) is not yet vendored here. Until
> it is, the authoritative list of entity types and attribute schemas comes from
> your operator in the Connector Brief. Validate against it before going live.

## 6. Proving conformance

```bash
ajar-conformance run --impl ./your-connector
```

Feeds each corpus fixture to your implementation, captures the bytes it emits,
and diffs them against the vectors. Exit 0 or 1, with a machine-readable report.
Runs offline in your CI. Green means your bytes are the bytes Ajar accepts —
without asking us.

## 7. What is frozen

Within `contract-v1` we will **never**:

- remove or renumber a protobuf field, or change its type;
- tighten validation so a previously-valid event becomes invalid;
- change the canonical encoding rules or the seal envelope layout;
- change the `ajar.ingest.<source_id>` subject scheme;
- remove an entity type or attribute a registered connector depends on.

We **may**, all additively:

- add optional fields (proto3 additive rules);
- add entity types and attribute schemas;
- add SDK helpers and languages.

A breaking shape becomes a **new** `schema_version` running alongside `v1`. Your
`v1` implementation keeps being accepted; migration is optional.

**The signature algorithm is lifecycled separately from the wire format** — the
envelope layout is frozen, the algorithm inside it is not guaranteed forever.
See [COMPATIBILITY.md](../COMPATIBILITY.md).

## 8. Getting registered

Ajar accepts events only from a registered identity. One handshake, no account:

**You send:** your `source_id`, the entity-type prefixes you will emit, and your
**public** key. Every connector in this repository derives that document for you:

```bash
ajar-tak-cot --profile ./your-config.toml
```

**You receive:** confirmation your key and types are registered, plus the NATS
endpoint and credentials.

Your private seed never leaves your environment, and neither does your source
code — only the profile document and the agreed data contract.
