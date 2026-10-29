#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every SDK manifest ships the same version, because the SDKs implement one
# contract and are released together as the tag vX.Y.Z. A drifting manifest
# publishes a package whose number means nothing — the Python SDK sat at 0.1.0
# through five releases of everything else.
#
# Connectors are not checked here: each carries its own version and is released
# on its own tag (scripts/release-target.sh guards those).
#
# Usage:  scripts/check-versions.sh [version]   (default: rust/Cargo.toml)
set -euo pipefail
want="${1:-$(grep -m1 '^version' rust/Cargo.toml | cut -d'"' -f2)}"

fail=0
check() { # <label> <found>
  if [ "$2" != "$want" ]; then
    echo "  $1: $2 (expected $want)"
    fail=1
  fi
}

check "rust/Cargo.toml"           "$(grep -m1 '^version' rust/Cargo.toml | cut -d'"' -f2)"
check "rust/examples/Cargo.toml"  "$(grep -m1 '^version' rust/examples/Cargo.toml | cut -d'"' -f2)"
check "python/pyproject.toml"     "$(grep -m1 '^version' python/pyproject.toml | cut -d'"' -f2)"
check "cpp/CMakeLists.txt"        "$(grep -m1 -oE 'VERSION [0-9]+\.[0-9]+\.[0-9]+' cpp/CMakeLists.txt | awk '{print $2}')"

if [ "$fail" -ne 0 ]; then
  echo "::error::the SDK manifests above disagree with the SDK version $want"
  exit 1
fi
echo "versions OK: every SDK manifest is $want"
