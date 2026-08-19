#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Package the C++ SDK as a self-contained source tarball.
#
# The extracted tree builds on its own — the vendored contract travels with it,
# so a consumer needs CMake, a compiler and protoc, and nothing from this
# repository. That is the point: an air-gapped site can take one file.
#
# Usage:  scripts/package-cpp.sh <version> [outdir]
set -euo pipefail
ver="${1:?usage: package-cpp.sh <version> [outdir]}"
out="${2:-dist}"
name="ajar-connector-cpp-${ver}"
stage="$(mktemp -d)/${name}"

mkdir -p "$stage" "$out"
# The SDK itself, minus build output and the examples' own build dirs.
tar cf - --exclude build --exclude .DS_Store cpp | tar xf - -C "$stage" --strip-components=1
# The contract it compiles against, at the path the CMake fallback expects.
mkdir -p "$stage/vendor/contract"
cp -R vendor/contract/. "$stage/vendor/contract/"
cp LICENSE NOTICE "$stage/" 2>/dev/null || true

tar czf "$out/${name}.tar.gz" -C "$(dirname "$stage")" "$name"
( cd "$out" && shasum -a 256 "${name}.tar.gz" > "${name}.tar.gz.sha256" 2>/dev/null \
  || sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256" )
rm -rf "$(dirname "$stage")"
echo "packaged $out/${name}.tar.gz"
