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

## Development workflow

`main` is the trunk and is always releasable. It is protected, so every change
lands through a pull request — no direct pushes.

- **External contributors:** fork the repository, create a short-lived branch,
  and open a PR against `main`.
- **Maintainers:** branch directly and open a PR.
- Each PR requires **green CI** (the per-language lint + conformance gates) and an
  **approving review from a Promaka maintainer** (see [CODEOWNERS](.github/CODEOWNERS))
  before it can merge.
- PRs are **squash-merged** to keep `main` history linear.
- Releases are git tags on `main` (e.g. `v0.1.0`). Pushing the tag is the whole
  release: CI builds and pushes the images, then creates the GitHub release from
  the tag's `CHANGELOG.md` entry. Nothing is published by hand, so a build that
  fails leaves no release rather than one whose images are missing. The tag must
  match the `version` in `rust/connectors/Cargo.toml`, and that version must have
  a `CHANGELOG.md` entry; both are checked before anything is pushed. A fix for an
  already-released line goes on a `release-x.y` maintenance branch and is tagged
  there.

## Before you push

Run the checks for the language(s) you changed, then the shared guards. CI runs
all of these on your PR.

**Rust**
```bash
cd rust && cargo fmt --all -- --check \
  && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cd examples && cargo fmt --all -- --check \
  && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

**Go**
```bash
cd go && gofmt -l . && go vet ./... && go test ./...
cd examples && gofmt -l . && go vet ./... && go test ./...
```

**Python**
```bash
cd python && python -m pytest -q && PYTHONPATH=. python conformance/golden_vectors.py
```

**C++**
```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release && cmake --build cpp/build -j \
  && ctest --test-dir cpp/build
```

**Always (shared guards)**
```bash
./scripts/check-license-headers.sh && ./scripts/check-contract.sh
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
