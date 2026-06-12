#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates go/eventpb/event.pb.go from the vendored event.proto. The output
# is committed so consumers need only `go build` — run this after re-vendoring.
#
# Requires: protoc and protoc-gen-go on PATH
#   brew install protobuf
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
set -euo pipefail
cd "$(dirname "$0")/.."

protoc \
  --proto_path=vendor/contract \
  --go_out=go \
  --go_opt=module=github.com/promaka/ajar-connectors/go \
  --go_opt=Mevent.proto=github.com/promaka/ajar-connectors/go/eventpb \
  event.proto

echo "regenerated go/eventpb/event.pb.go"
