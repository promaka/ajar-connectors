#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates cpp/embedded/generated/event.pb.{c,h} (nanopb, no-heap static
# types) from the vendored event.proto + cpp/embedded/event.options. The output
# is committed so a build needs only the vendored nanopb runtime — run this only
# after re-vendoring the contract or changing the .options sizing.
#
# Requires: protoc, and the nanopb generator on PATH (pip install nanopb).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

protoc --proto_path=vendor/contract -o "$tmp/event.fds" vendor/contract/event.proto
nanopb_generator -f cpp/embedded/event.options -D cpp/embedded/generated "$tmp/event.fds"

echo "regenerated cpp/embedded/generated/event.pb.{c,h}"
