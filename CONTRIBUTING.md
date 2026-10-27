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
- **Stacked PRs target `main` before their parent merges.** A squash merge
  replaces the parent's commits with one new commit, so a child still pointing at
  the parent branch is left behind: its own merge lands in a branch that no longer
  feeds `main`, and the work silently never ships. When a change builds on another:
  1. open it against the parent branch and say so in the body;
  2. the moment the parent merges, rebase the child onto `main` and retarget it;
  3. never delete a parent branch while a child still points at it — a closed PR
     whose base is gone cannot be reopened and must be raised again from scratch.
- Releases are per package; see [Releases](#releases) below.

## Releases

Each connector, the SDK and the connector Helm chart carry their own version and
are released on their own. Merging a version bump to `main` is the release, so
the review of that PR is the decision to ship.

| Package | Version lives in | Tag | What CI publishes |
|---------|------------------|-----|-------------------|
| a connector or tool with `[package.metadata.ajar] release = true` | its `Cargo.toml` | `<name>-vX.Y.Z` | image `ajar-connector-<name>:X.Y.Z` (unless `image = false`), binaries tarball, GitHub release |
| the connector chart, with the annotation `ajar.release: "true"` | `deploy/helm/connector/Chart.yaml` | `chart-vX.Y.Z` | `oci://ghcr.io/promaka/charts/connector` |
| the SDK (Rust, Go, Python, C++) | `rust/Cargo.toml`, `python/pyproject.toml`, `cpp/CMakeLists.txt`, in lockstep | `vX.Y.Z` | crates.io, PyPI, `go/vX.Y.Z`, C++ tarball, GitHub release |

To release a connector:

1. In your PR, bump `version` in `rust/connectors/<name>/Cargo.toml` and add a
   `## [X.Y.Z] - <date>` entry to its `CHANGELOG.md`. Use semver: a fix is a
   patch, a new field or option a minor, and renaming or removing an emitted
   entity type, attribute or config key a major, because that breaks a site's
   ontology and policy even though everything still compiles.
2. Merge. `tag-releases.yml` tags `<name>-vX.Y.Z` and `release-connector.yml`
   builds and publishes that package only.

`tag-releases` releases every package whose current version has no tag yet
(`scripts/release-tags.sh`), not only the ones the last merge bumped. A run that
stopped before tagging (cancelled, or refused by the guard) is caught up by the
next merge to `main`, or when you run `tag-releases` from the Actions tab. Once
the tag exists, a failed build is re-run with `release-connector` from the
Actions tab. A version below one already released is refused, and nothing ships
until it is fixed.

To start releasing a connector, set `release = true` **and bump its version**
in the same PR. Its current version was already published by the last suite
release (the `<name>-v0.6.5` tags record that), and a version is never
published twice.

A change to a connector without a bump ships at its next bump. The advisory
`bump-check` job (`scripts/check-bumps.sh`) points out changed packages that
were not bumped, including the connectors that a change to `common`, a shared
crate or `Cargo.lock` reaches; it never fails the build, since a refactor or a
test may not need a release. A bumped version without a changelog entry does
fail CI, because its release would be refused.

`scripts/release-target.sh <tag>` runs the same guard locally: it resolves a tag
and refuses it unless the manifest version and the changelog entry match. A tag
pushed by hand releases the same way, and the `release-connector` workflow can be
re-run for an existing tag from the Actions tab.

The SDK is still released by pushing `vX.Y.Z` on `main`: `scripts/check-versions.sh`
and `scripts/check-doc-pins.sh` must pass for that version, and the root
`CHANGELOG.md` needs its entry. A fix for an already-released SDK line goes on a
`release-x.y` maintenance branch and is tagged there.

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
