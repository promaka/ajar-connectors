<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security policy

This SDK builds and **cryptographically signs** the events that flow into Ajar,
so the integrity of its signing and canonical-encoding code is security-critical.
We take reports seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately via **GitHub private vulnerability reporting** — the
**Security → Report a vulnerability** tab on this repository. (Maintainers:
enable it under Settings → Code security → Private vulnerability reporting.)

Please include:

- the affected component (language SDK, contract, deploy chart) and version /
  commit,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- any suggested fix.

We aim to acknowledge a report within **3 business days** and to agree a
disclosure timeline with you. Please give us a reasonable window to fix before
any public disclosure.

## What's in scope

- The signing / seal path (`seal`, key handling) in any language SDK.
- The canonical-encoding path (`canonical_bytes`, `EventBuilder` invariants) —
  in particular anything that could make two SDKs disagree on bytes, or let a
  non-canonical event pass `build()`.
- The vendored contract integrity checks ([scripts/check-contract.sh](scripts/check-contract.sh))
  and golden vectors.
- The deployment artifacts under [deploy/](deploy/) (key injection, container
  hardening).

## What's out of scope

- **Ajar Core** (verification, policy, ontology, storage) — that lives in the
  private `promaka/ajar` repo; report Core issues through that project.
- The **published conformance seed** (`0x47…`). It is intentionally public
  and documented as test-only — using them to sign is operator/connector
  misconfiguration, not a vulnerability in the SDK. Production connectors must
  load their own secret seed (see [ONBOARDING.md §6](ONBOARDING.md)).
- Vulnerabilities in third-party dependencies should generally be reported
  upstream; tell us too if this SDK's use of them is affected.

## Handling keys safely (operational reminder)

- Generate a unique Ed25519 key per connector ([scripts/gen-connector-key.sh](scripts/gen-connector-key.sh)).
- Keep the 32-byte **private seed** in a secret manager / HSM / locked-down file;
  never commit it. The SDK takes the key by reference and never logs or serializes
  it. In Kubernetes, inject it as a read-only file from a Secret (see
  [deploy/helm/connector](deploy/helm/connector/)), not as an env value.
- Only the **public** key leaves your control — it goes in the connector profile
  you register with the operator.
</content>

## Key material

No private key, certificate or credential has ever been committed to this
repository, and CI proves it stays that way: gitleaks scans the full git
history on every pull request, and `.gitignore` refuses `*.key` and `*.seed`.

One published constant exists: the conformance test seed (32 bytes of 0x47) in
`vendor/contract/vectors.json`. Byte-exact golden vectors require every SDK to
sign with the same seed, the same practice as RFC 8032's published test
vectors. It authorises nothing: no production registry will ever contain its
public half. Every other key in the system is minted where it runs — the demo
stack mints a fresh keypair at startup, dry-run modes mint an ephemeral
throwaway per run, and production seeds are operator-generated.

The allowlist in `.gitleaks.toml` names exactly what is permitted and the
reason each entry exists.
