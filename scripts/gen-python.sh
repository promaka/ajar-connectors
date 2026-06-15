#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates python/ajar_connector/event_pb2.py from the vendored event.proto.
# The output is committed so consumers need only `pip install` — run this after
# re-vendoring the contract.
#
# Requires: protoc (brew install protobuf)
set -euo pipefail
cd "$(dirname "$0")/.."

protoc --python_out=python/ajar_connector --proto_path=vendor/contract event.proto

echo "regenerated python/ajar_connector/event_pb2.py"
