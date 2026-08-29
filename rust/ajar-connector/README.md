<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connector

Rust SDK for building connectors to Ajar, a defence data integration and
governance plane. A connector turns a system's native data into Ajar's
canonical, signed event; this crate does the canonical encoding and the
Ed25519 seal, and verifies envelopes in either direction.

```rust
use ajar_connector::{canonical_bytes, seal, verify, EventBuilder, SigningKey};

let key = SigningKey::from_bytes(&seed);            // your registered key
let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
    .new_id()
    .now()
    .location(25.27, 51.52, 10600.0)
    .attribute("speed", "231.50")                    // governed, m/s
    .metadata("icao", "4CA2D6")                      // ungoverned, native id
    .payload(raw_frame)                              // your bytes, verbatim
    .build()?;

let sealed = seal(&canonical_bytes(&event), &key);   // signature ++ canonical
let canonical = verify(&sealed, &key.verifying_key())?;
```

Byte-compatibility is the acceptance test: five independent SDK
implementations reproduce the same golden vectors, and `ajar-conformance`
proves any implementation offline. The wire contract, the mapping guide and
the onboarding path live in the repository:
<https://github.com/promaka/ajar-connectors>.

The crate carries the vendored `event.proto` it compiles, pinned to the
contract the repository publishes. `protoc` is bundled; a plain `cargo build`
needs no system dependencies.
