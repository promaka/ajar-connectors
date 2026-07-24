<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-tak-cot

Ingress connector for **TAK / Cursor-on-Target (CoT)**. It listens for the CoT
situational-awareness messages that ATAK, WinTAK, and TAK-aware sensors already
broadcast, normalizes each track into a canonical Ajar `Event`, seals it with the
connector's Ed25519 key, and publishes it to Core's ingest subject.

Nothing on the TAK side changes. The connector speaks CoT as it is already spoken
on the wire; the fielded kit does not know Ajar exists.

## Model

```
CoT (UDP multicast) ──▶ ajar-tak-cot ──▶ canonical Event ──▶ seal ──▶ NATS  ajar.ingest.<source_id>
     untrusted edge         parse            (SDK)          (Ed25519)         (mTLS to Core)
```

The connector holds no Core secrets — only its own signing key. Core trusts the
signature, not the pipe: it verifies the seal against the public key registered
for `source_id` and drops anything that fails. See
[HOW_IT_WORKS.md](../../../HOW_IT_WORKS.md).

## Configure

Copy [`tak-cot.example.toml`](tak-cot.example.toml) and edit it. Everything an
operator sets is data — a second feed is a second config file, not a rebuild.

| Key | Meaning |
|-----|---------|
| `source_id` | this connector's Ajar identity; its signing key is registered in Core against this id |
| `nats_url` | Core's NATS endpoint (`tls://host:443` in production, `nats://…` for local dev) |
| `subject_prefix` | ingest prefix; publishes to `<prefix>.<source_id>` (default `ajar.ingest`) |
| `signing_key_path` | the connector's Ed25519 seed: 32 raw bytes or a 64-char hex file — secret |
| `[transport]` | `kind` = `udp-multicast` (CoT default) or `udp`; `bind`; `group` (multicast only) |
| `[entity_map]` | optional CoT-type → Ajar entity-type overrides |

CoT types map to Ajar entity types by battle dimension (air → `mim:aircraft`,
sea surface → `mim:vessel`); anything else falls back to `x:cot:<type>` so no
track is dropped for lack of a mapping. Override any specific code in
`[entity_map]`. The final say on what Core accepts is the sovereign's ontology
and the connector's registered namespaces.

## Tactical attributes (what a COP reads)

Beyond position, the connector extracts the attributes an operating picture needs:

| Attribute | From | Notes |
|-----------|------|------------|
| `affiliation` | the type's 2nd field: `f`→`friendly`, `h`→`hostile`, `n`→`neutral`, `u`/other→`unknown` | always set — a track is never blank |
| `callsign` | `<detail><contact callsign="…"/>` | if present |
| confidence | `<detail><confidence>0.87</confidence>` or `<confidence value="87"/>` (percent accepted) | the event's `confidence` field (if present) |

Routing is **per attribute**: a key listed in the config's `governed_attributes`
rides as a governed attribute (type-validated by the ontology); every other key
rides as metadata (always accepted). The safe default — an empty list — routes
everything to metadata, so an undeclared key can never cost a track. Once the
deployment's ontology declares them, set:

```toml
governed_attributes = ["affiliation", "callsign"]
```

The full attribute reference (all connectors, semantics, units) is
[ATTRIBUTES.md](../ATTRIBUTES.md).

## Run

```bash
# Local dev (plaintext NATS)
ajar-tak-cot ./tak-cot.toml

# Production: client cert is the connector's transport identity (CN = source_id)
export AJAR_TLS_CA=/etc/ajar/ca.pem
export AJAR_TLS_CERT=/etc/ajar/tak-field-1.crt
export AJAR_TLS_KEY=/etc/ajar/tak-field-1.key
export AJAR_HEALTH_ADDR=0.0.0.0:9110   # optional: /healthz and /metrics
ajar-tak-cot /etc/ajar/tak-cot.toml
```

`RUST_LOG=debug` raises log detail. Dropped frames are counted and logged with
the reason; `/metrics` exposes `connector_received_total`,
`connector_published_total`, `connector_rejected_total`.

## Register the key

The connector signs with its own key; Core must hold the matching public key
against `source_id` before it will accept events. Generate a seed, register its
public half with your operator, and keep the private seed safe (see
[SECURITY.md](../../../SECURITY.md)). Rotating the key means re-registering the
public half.

## Security note

CoT is an **untrusted edge**: field messages can be malformed, truncated, or
hostile. The parser uses a real XML reader, never panics, and never fabricates a
field — every failure is a typed error that is counted and logged, never silently
swallowed. Trust is established downstream by the seal, which Core verifies.

## Conformance

`cargo test` runs, alongside the unit tests:

- **byte-identity to the SDK** — the connector emits exactly the bytes the SDK's
  `EventBuilder` produces, adding no encoding of its own;
- **seal verifies under the published contract key** — sealing with the contract
  test seed yields an envelope that verifies under the published verifying key;
- **a pinned canonical hash** — locking the CoT→event mapping against drift;
- **fuzz** — thousands of arbitrary and CoT-shaped inputs, asserting the parser
  never panics.

## Adding another situational-awareness format

This connector is a CoT `FrameParser` plugged into the shared
[`ajar-connector-common`](../common) runtime; the binary in `src/main.rs` is only
the wiring. Another UDP-broadcast format (ASTERIX, MAVLink, AIS/NMEA) is the same
shape: implement `FrameParser` for that wire format and hand it, with a
`FrameSource`, to `common::run`.
