<!-- SPDX-License-Identifier: Apache-2.0 -->
# Build an Ajar connector — the brief

*This is the short version — a **template**. Ajar is run by many independent
operators (sovereigns, programmes, demos), and each runs their own Core, so the
values below are **specific to the deployment you're connecting to**. The
**operator who onboarded you** fills the `<…>` blanks in a copy of this page and
sends it to you; if a value is missing, ask them. Vendor: the whole job is ~15
lines of code and an afternoon.*

---

## What you're building

A small program that turns your data into a **signed event** and publishes it to
a message bus (NATS). Ajar verifies your signature and stores it. The SDK does
the signing and encoding; **you write one mapping function.**

Your connector's code stays yours — it's never published. The only things you
send us are your connector's **public** key and the **data contract** below; they
go to us (your operator) privately, not to any public repository.

## What we (your operator) are giving you

| | |
|---|---|
| **source_id** | `<your-source-id, e.g. acme-radar-1>` |
| **entity type(s)** you may emit | `<e.g. mim:aircraft>` |
| **attributes** (if any) for those types | `<e.g. none, or: heading (deg), speed (kn)>` |
| **NATS endpoint** to publish to | `<e.g. tls://nats.ourgrid.example:443>` |
| **mTLS materials** (we issue these) | `<CA PEM + your client cert (CN=source_id) + key>` |
| **contact** for questions / your public key | `<e.g. connectors@our-org.example>` |
| **SDK version to pin** | `v0.1.0` |

## What you do — 5 steps

1. **Copy a starting point** for your language and pin the SDK to `v0.1.0`:
   - **Rust** — copy [rust/examples/connector-template](rust/examples/connector-template/)
   - **Python** — copy [python/examples/connector_template.py](python/examples/connector_template.py)
   - **Go** — copy [go/examples/connector-template](go/examples/connector-template/)
   - **C++** — copy [cpp/examples/connector_template.cpp](cpp/examples/connector_template.cpp); build with CMake per **[cpp/README.md](cpp/README.md)**
2. **Edit two things:** the shape of *your* record (**`EDIT 1`**) and the mapping
   to an event (**`EDIT 2`**) — use the **entity type** above, and add an
   `.attribute(k, v)` only for the attributes listed above. Both spots are marked
   in every template.
3. **Make a key** and send us the **public** half:
   ```bash
   scripts/gen-connector-key.sh <your-source-id>
   ```
   Send us the printed public key (we register it); keep the `.seed` file secret.
4. **See it work, no infra** (`--dry-run` builds + seals + prints, no NATS, no
   mTLS needed) — every template reads one record per line on stdin:
   ```bash
   echo '<one sample record>' | <run the template> --dry-run   # Go uses -dry-run
   ```
   Rust/Python/Go read JSON; the C++ template reads `lat lon alt_m quality` —
   swap in your own parser. You should see sealed events printed.
5. **Go live:** run the same binary pointed at the NATS endpoint above, with your
   real seed and the mTLS env vars we issue:
   ```bash
   AJAR_TLS_CA=ca.pem AJAR_TLS_CERT=client.pem AJAR_TLS_KEY=client.key \
   AJAR_SIGNING_SEED=<your>.seed AJAR_SOURCE_ID=<your-source-id> \
   NATS_URL=<tls endpoint above>  <run your connector>
   ```
   Done — and you never need to upgrade ([why](COMPATIBILITY.md)).

## The rules that matter (the SDK enforces them for you)

- Events are **canonical + signed**; if `build()` succeeds, the shape is valid.
- Use **only** the entity type(s) and attributes we agreed above — anything else
  is rejected.
- Don't set `received_at` (we stamp it). Timestamps are RFC 3339 UTC.

## Verify you're byte-compatible (optional but recommended)

Run the conformance gate for your language (proves your build produces the exact
bytes Ajar accepts) — commands in [ONBOARDING.md §9](ONBOARDING.md).

---

**More detail:** [ONBOARDING.md](ONBOARDING.md) (full guide) ·
[HOW_IT_WORKS.md](HOW_IT_WORKS.md) (how/why) ·
[COMPATIBILITY.md](COMPATIBILITY.md) (the build-once promise).
</content>
