#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Flags drift between the vendored contract and the known-good hashes.
# Core is private, so the vendored copy is the SDK's source of truth; if it
# changes without an intentional re-vendor + hash bump, the golden vectors may
# silently stop meaning anything. This guards that.
set -euo pipefail
cd "$(dirname "$0")/.."

if shasum -a 256 --check --status scripts/contract.sha256; then
  echo "contract OK: vendored files match scripts/contract.sha256"
else
  echo "ERROR: vendored contract diverges from scripts/contract.sha256" >&2
  echo "If this was an intentional re-vendor from core, update the pin with:" >&2
  echo "  shasum -a 256 vendor/contract/event.proto vendor/contract/vectors.json vendor/contract/corpus/*.json > scripts/contract.sha256" >&2
  echo "and bump vendor/contract/CONTRACT_VERSION + PROVENANCE.md." >&2
  exit 1
fi
