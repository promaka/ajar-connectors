#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every language manifest ships the same version, because they all implement one
# contract and are released together. A drifting manifest publishes a package
# whose number means nothing — the Python SDK sat at 0.1.0 through five releases
# of everything else.
#
# Usage:  scripts/check-versions.sh [version]   (default: rust/connectors/Cargo.toml)
set -euo pipefail
want="${1:-$(grep -m1 '^version' rust/connectors/Cargo.toml | cut -d'"' -f2)}"

fail=0
check() { # <label> <found>
  if [ "$2" != "$want" ]; then
    echo "  $1: $2 (expected $want)"
    fail=1
  fi
}

check "rust/Cargo.toml"           "$(grep -m1 '^version' rust/Cargo.toml | cut -d'"' -f2)"
check "rust/connectors/Cargo.toml" "$(grep -m1 '^version' rust/connectors/Cargo.toml | cut -d'"' -f2)"
check "rust/examples/Cargo.toml"  "$(grep -m1 '^version' rust/examples/Cargo.toml | cut -d'"' -f2)"
check "python/pyproject.toml"     "$(grep -m1 '^version' python/pyproject.toml | cut -d'"' -f2)"
check "cpp/CMakeLists.txt"        "$(grep -m1 -oE 'VERSION [0-9]+\.[0-9]+\.[0-9]+' cpp/CMakeLists.txt | awk '{print $2}')"

if [ "$fail" -ne 0 ]; then
  echo "::error::the manifests above disagree with the release version $want"
  exit 1
fi
echo "versions OK: every manifest is $want"
