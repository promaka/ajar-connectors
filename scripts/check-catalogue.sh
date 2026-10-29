#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The "Overview" table in CONNECTORS.md names each released package's latest
# version and links its release. Fail when a row is missing or names a version
# other than the one in the package's Cargo.toml (or Chart.yaml), so the table is
# updated in the PR that bumps the version.
#
# Usage:  scripts/check-catalogue.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
doc=CONNECTORS.md
failed=0

expect() { # <tag-name> <version>
  local link="releases/tag/$1-v$2)"
  if ! grep -qF "[$2](https://github.com/promaka/ajar-connectors/$link" "$doc"; then
    echo "::error file=$doc::$1 is at $2, but the table in $doc does not link $1-v$2; update its row"
    failed=1
  elif [ "$(grep -cF "releases/tag/$1-v" "$doc")" -ne 1 ]; then
    echo "::error file=$doc::$doc links more than one release of $1; keep one row with the latest"
    failed=1
  fi
}

while IFS=$'\t' read -r name version; do
  expect "$name" "$version"
done < <(for ws in rust/connectors rust/examples; do
  cargo metadata --no-deps --format-version 1 --manifest-path "$ws/Cargo.toml" \
    | jq -r '.packages[] | select(.metadata.ajar.release == true)
             | [(.name | ltrimstr("ajar-")), .version] | @tsv'
done)
chart=deploy/helm/connector/Chart.yaml
if grep -qE '^ +ajar\.release: *"?true"?' "$chart"; then
  expect chart "$(grep -m1 '^version:' "$chart" | awk '{print $2}')"
fi

[ "$failed" -eq 0 ] && echo "catalogue OK: every released package's row names its version"
exit "$failed"
