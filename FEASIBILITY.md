<!-- SPDX-License-Identifier: Apache-2.0 -->
# Format feasibility — why these connectors, and not those

This repo ships connectors for a deliberate set of formats and, just as
deliberately, does **not** ship others. This document records the rule we apply and
the per-format verdicts, so the "why these, not those" decision is on the record for
contributors and evaluators. It contains **no controlled technical content** — only
the sourcing and rigor rationale.

## The bar every connector must clear

A format becomes a shipped connector only when a decoder for it can be:

1. **Lossless** — it never drops a wire field; the raw frame is sealed verbatim into
   `Event.payload` so a later ontology can re-extract what today's parser doesn't map.
2. **Bit-/byte-exact** — the field layouts are decoded correctly, not approximated.
3. **Cross-checked against an independent oracle** — an open reference
   implementation and/or published sample vectors we can verify against. *Without an
   oracle, we do not build* — we will not decode blind against our own reading of a
   gated specification and present the result as trustworthy.
4. **Legally shippable in the open** — the format's definition is public or
   releasable, not export-controlled technical data whose transcription into public
   code carries ITAR/EAR exposure.

A format that fails (3) or (4) is not a coding gap we close by trying harder; it is a
boundary. The right response is to wait for a reference decoder / real capture, or to
handle the format under a cleared, customer-specific engagement — never to ship a
blind or legally-exposed decoder into a public repository.

## Shipping today

| Format | Domain | Oracle used to verify |
|---|---|---|
| ADS-B | Cooperative air | Open decoders + reference message set |
| ASTERIX CAT021 / 048 / 062 | Air surveillance (cooperative, primary, fused) | python-asterix + Wireshark |
| AIS (NMEA) | Maritime surface | Open AIS decoders |
| MAVLink | Small / commercial UAS | Open MAVLink libraries |
| STANAG 4609 / MISB ST 0601 (KLV) | ISR full-motion-video metadata | MISB reference + checksum |
| STANAG 4607 (GMTI) | Ground moving-target radar | Reference decoders |
| STANAG 4676 (NITS, Ed. B) | ISR fused tracks | `bradh/jim` Edition-B reference + samples |
| Cursor-on-Target (TAK) | Tactical edge C2 | Public CoT schema + open libraries |
| `generic` | Any config-mapped JSON / CSV / NMEA | n/a (operator-supplied mapping) |

## Assessed and deferred

| Format | Standard | Verdict | Why |
|---|---|---|---|
| **NFFI / FFI** | STANAG 5527 | **NO-GO** | No open reference implementation, no public sample vectors, and the IP1/IP2 transport binding lives in a gated STANAG. Public XSD covers the payload only — no independent oracle. |
| **Link 16 — waveform** | STANAG 5516 | **NO-GO** | Classified; and irrelevant — real feeds are ingested post-gateway, already demodulated/decrypted. |
| **Link 16 — J-series message layer** | MIL-STD-6016 | **CONDITIONAL (narrow)** | Word framing + message-type identification is verifiable against Wireshark's dissector; **field-level decode is NO-GO** — no independent field-level oracle, and the layouts live only in export-controlled (ITAR USML XI) technical data. |
| **JREAP-C** | MIL-STD-3011 / STANAG 5518 | **NO-GO** | Gated spec, no open decoder, no public capture. Payload is J-series, so it inherits Link 16's wall. |
| **VMF** | MIL-STD-6017 | **CONDITIONAL (header only)** | The header has a public spec + an MIT reference (`vmf-parser`); the K-series bodies have no public spec, no oracle, no vectors. |
| **Link 22** | STANAG 5522 | **NO-GO** | Restricted-to-classified by edition; no open implementation. |
| **Link 11 / 11B** | STANAG 5511 / 5512 | **NO-GO** | Baseline spec purchasable, but no independent field-level oracle and no public vectors; crypto volume is classified. |
| **STANAG 4586** (military UAS C2) | AEP-84 | **GO — building** | DLI message set is fixed-field big-endian with published field tables; spec is NATO UNCLASSIFIED and freely public (no ITAR/EAR); a GPL reference implementation exists as an independent cross-check. Cleaner oracle + export posture than 4676. Building an Edition 2 baseline (wrapper + core messages), lossless over the full frame. |

## Two standing principles

- **Never decode blind against a gated spec.** If we cannot cross-check a decoder
  against an independent oracle, we do not ship it. Correct-looking output from an
  unverifiable parser is exactly the black box a sovereign operator is trying to
  escape.
- **Never ship export-controlled technical data in a public repo.** Some message
  *formats* — not just waveforms — are ITAR/EAR-controlled. Those are handled as a
  cleared, customer-specific capability, built from legitimately-sourced material and
  verified against a real oracle, not transcribed from a gated document into open
  code. The `vmf-parser` model — ship the parsing engine, let the operator supply the
  controlled tables — is the pattern where a split is possible.

*This is engineering-rationale documentation, not legal advice. Any release touching
export-controlled material should have a written export-counsel determination first.*
