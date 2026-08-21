<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compatibility & stability guarantee

**The promise: build a connector once, and it keeps working — you are never
forced to upgrade.**

This page explains exactly what that promise covers, why it holds, and the few
things you should do to rely on it.

## Why "build once" works

A connector is a **binary you build and run**. It does not phone home and does
not auto-update. So whether it keeps working depends on exactly one thing: Ajar
Core continuing to accept the bytes it emits. Those bytes are defined by the
**wire contract**, which is frozen.

There are two layers; only the first is something you depend on at runtime:

| Layer | What it is | Stability |
|-------|------------|-----------|
| **Wire format** | the canonical `Event` encoding (`event.proto`, `schema_version="v1"`), the seal envelope layout (`signature ++ canonical`), and the `ajar.ingest.<source_id>` subject | **Frozen. A connector built against `v1` is accepted forever.** |
| **Signature algorithm** | the primitive used to produce the seal (today Ed25519) | **Lifecycled, not frozen** — see [Cryptographic lifecycle](#cryptographic-lifecycle). Governed by published notice, never by a silent change. |
| **SDK API** | the source convenience (`EventBuilder`, `seal`, `ConnectorProfile`, …) | A convenience for *building* the bytes. Changing it only affects you if you *choose* to rebuild against a newer SDK. Your running binary is unaffected. |

The split matters. The *format* promise is what lets you deploy a connector and
leave it alone; it is deliberately permanent. The *algorithm* is a different kind
of commitment: no cryptographic primitive is appropriate forever, and a vendor who
promises one is making a promise that expires against their customers' own
security policy rather than against their roadmap.

The conformance gate (golden vectors in [`vendor/contract/`](vendor/contract/))
is what enforces the frozen wire: every SDK, in every release, must reproduce the
exact `v1` bytes. If a change ever altered them, the gate fails and the release
does not ship.

## What we (the operator) guarantee for `contract-v1`

We will **never**, within `v1`:

- remove or renumber a protobuf field, or change its type;
- tighten validation on an existing field so a previously-valid event becomes
  invalid;
- change the canonical encoding rules or the seal envelope layout;
- change the `ajar.ingest.<source_id>` subject scheme;
- remove an entity type or attribute from the ontology that a registered
  connector depends on.

We **may** (all backward-compatible, all additive):

- add new optional fields (proto3 additive rules);
- add new entity types and new attribute schemas;
- add new SDK helpers and languages.

If we ever need a breaking shape, it will be a **new** `schema_version` (`v2`)
that runs **alongside** `v1` — your `v1` connector keeps being accepted; you
migrate only if and when you want the new capability.

## Cryptographic lifecycle

The seal is a signature, and signature algorithms have finite lives. National and
alliance crypto catalogues (BSI TR-02102-1, SOG-IS, the ECCG agreed mechanisms)
publish which primitives are acceptable, and they revise those lists. Post-quantum
migration will move every one of them within the decade. A promise to sign with
one primitive forever would therefore be a promise to eventually fall outside our
own customers' security policy — so we do not make it.

What we guarantee instead:

- **The envelope layout is frozen** (`signature ++ canonical`). Algorithm changes
  are versioned, never silent, and never a reinterpretation of existing bytes.
- **Sunsetting an algorithm requires published notice**, stated as a date, not a
  release. We announce, then wait; we do not deprecate by shipping.
- **Events sealed with a sunset algorithm stay verifiable** through the notice
  period, so historical provenance is never invalidated by a migration.
- **A new algorithm is a new envelope version that runs alongside the old**, on
  the same terms as a `v2` schema: your existing connector keeps being accepted,
  and you migrate when you choose to.

The practical consequence for an accreditor: our changes do not re-open your
accreditation. Security accreditation of a fielded system is measured in months,
and re-accreditation after a supplier change is the expensive part. A frozen
format plus an announced, dated algorithm lifecycle means you can plan a crypto
migration into your own review cycle instead of discovering it in ours.

## What you should do to rely on this

1. **Pin a released tag, not a branch.** Depend on a tag (e.g. `v0.5.5`), never
   `branch = "main"` — `main` moves. With a pinned tag, even your *next rebuild*
   is reproducible.
   - Rust: `ajar-connector = { git = "https://github.com/promaka/ajar-connectors", tag = "v0.5.5" }`
   - Go: `go get github.com/promaka/ajar-connectors/go/ajarconnector@v0.5.5`
   - Python: `pip install "git+https://github.com/promaka/ajar-connectors.git@v0.5.5#subdirectory=python"`
   - C++: check out the `v0.5.5` tag (or vendor it) and build per [cpp/README.md](cpp/README.md).

   On an air-gapped or accredited network none of these will resolve. Vendor the
   full dependency closure at the tag on a connected machine and carry it across —
   see the offline bundle recipe in [ONBOARDING.md](ONBOARDING.md#5-build-it).
2. **Keep your signing key.** Your identity is your key; rotating it requires
   re-registering the public half with your operator. Store the private seed
   safely (see [SECURITY.md](SECURITY.md)).
3. **Agree your entity types up front.** What's frozen is the *format*; what your
   events mean (entity types, attribute schemas) is agreed with your operator at
   onboarding. Use the types they registered for you.

## Upgrading is optional

You'd only ever pull a newer SDK tag to get a bugfix or a new helper *you want* —
never because something forced you. When you do, the conformance gate guarantees
the bytes are still `v1`-compatible, so a rebuild is safe.

## Versioning summary

- **`contract-v<N>`** — the wire contract. Bumps only for a breaking shape, and
  old versions keep being accepted. Pinned in [`vendor/contract/CONTRACT_VERSION`](vendor/contract/CONTRACT_VERSION).
- **SDK `vMAJOR.MINOR.PATCH`** — the library. Pre-`1.0`, the source API may see
  small additive or renaming changes between minors; none of them change the
  wire, and none affect an already-built binary.

Questions about a specific guarantee? See [SECURITY.md](SECURITY.md) to reach us,
or [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for the mechanics behind the frozen wire.
</content>
