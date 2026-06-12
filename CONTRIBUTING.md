<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing

Thanks for helping build the Ajar connector SDK.

## Ground rules

1. **License & headers.** This project is Apache-2.0. Every source file must
   start with `SPDX-License-Identifier: Apache-2.0`. CI enforces this
   (`scripts/check-license-headers.sh`).
2. **No dependency on Ajar core.** The SDK is standalone. Types come from the
   vendored `vendor/contract/event.proto`; never import a private `ajar-*`
   crate. The seal spec is reimplemented here, not borrowed.
3. **The conformance gate is the contract.** If your change can't reproduce
   every hash in `vendor/contract/vectors.json`, it's wrong. Run:
   ```bash
   cd rust && cargo test -p conformance --test golden_vectors
   ```
4. **No production secrets.** The golden signing seed is TEST-ONLY.

## DCO sign-off

Contributions are accepted under the [Developer Certificate of
Origin](https://developercertificate.org/). Sign off every commit:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer, certifying
you have the right to submit the work under Apache-2.0.

## Before you push

```bash
cd rust
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd .. && ./scripts/check-license-headers.sh && ./scripts/check-contract.sh
```

## Re-vendoring the contract

The contract lives in core (private). When it changes, copy the updated
`event.proto`, `vectors.json`, and `corpus/*.json` into `vendor/contract/`, then:

```bash
shasum -a 256 vendor/contract/event.proto vendor/contract/vectors.json \
  vendor/contract/corpus/*.json > scripts/contract.sha256
```

Bump `vendor/contract/CONTRACT_VERSION` and update `PROVENANCE.md` with the new
source commit.
