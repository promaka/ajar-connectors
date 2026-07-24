<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-tak-egress

The **info-egress** relay: governed CoT from Ajar Core out to a **TAK Server**,
so TAK users see the governed common operating picture on their existing kit.

This is the mirror image of the ingress connectors — and deliberately dumber.

## Model

```
Core ──governed CoT──▶ NATS  ajar.egress.cot.*  ──▶ ajar-tak-egress ──TLS──▶ TAK Server :8089 ──▶ ATAK/WinTAK
      (verified, policy-       (mTLS subscribe)        verbatim relay          (client cert
       filtered, rendered)                             no parse, no sign        enrolled)
```

**Pure transport.** Core has already done all governance — signature
verification, policy, ontology, any anonymization — *before* publishing to the
egress subject. This relay does **not** sign, parse, alter, filter, or "improve"
the CoT: each NATS payload is written to the TAK stream **byte-verbatim**. That
verbatim rule is what preserves the governed guarantee end-to-end; any
transformation belongs in Core, never here.

TAK's streaming input parses concatenated CoT XML event-by-event (TAK Protocol
v0). Optional protobuf-v1 negotiation is a possible later addition.

## Identity — two certificates (onboarding)

| Certificate | Issued by | Grants |
|---|---|---|
| `AJAR_TLS_CA/CERT/KEY` env | the Ajar operator's PKI | mTLS to Ajar NATS; the NATS authz for this CN is **subscribe-only** on `ajar.egress.cot.*` (the outbound analogue of ingest onboarding — an "egress-reader" entry, no publish rights) |
| `[tak] tls_cert/tls_key` | the TAK Server's enrollment | client authentication on the TAK Server streaming input |

## Configure & run

Copy [`tak-egress.example.toml`](tak-egress.example.toml).

```bash
export AJAR_TLS_CA=/etc/ajar/ca.pem AJAR_TLS_CERT=/etc/ajar/egress-reader.crt AJAR_TLS_KEY=/etc/ajar/egress-reader.key
export AJAR_HEALTH_ADDR=0.0.0.0:9110   # optional: /healthz and /metrics
ajar-tak-egress /etc/ajar/tak-egress.toml
```

## Resilience

- **Ajar side**: async-nats reconnects by itself (same as every connector).
- **TAK side**: reconnect with pacing on any drop; connects lazily so startup
  never blocks on the TAK Server.
- **TAK down**: events queue in a bounded in-memory buffer (`buffer_max`). On
  overflow the **oldest** event is dropped — the freshest picture wins — and the
  gap metric increments. Bounded and lossy **by design** for a live map feed;
  a durable never-gap egress is a deliberate non-goal here (revisit if a feed
  must never gap).

## Metrics (`AJAR_HEALTH_ADDR`)

`egress_delivered_total` · `egress_gap_dropped_total` ·
`egress_tak_reconnects_total` · `egress_tak_link_up` (1/0 gauge)

## Tests

`cargo test` runs against a real mutual-TLS CoT sink minted in-test (throwaway
CA/server/client certs): byte-identical delivery, and same-link reconnection
across forced mid-stream drops. The full NATS-in-the-loop test is env-gated —
set `AJAR_TEST_NATS_URL` to run it against a live broker.

## Out of scope (deliberately)

No CoT parsing or rewriting, no signing, no anonymization, no effector-cue path.
The effector cue delivery (ADR-0024) will later reuse this transport — an
authorized signed CoT tasking message routed down the same TLS stream — which is
why the TAK send path is a reusable [`TakLink`](src/tak.rs), not code inlined in
the subscribe loop.
