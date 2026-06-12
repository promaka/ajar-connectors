#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails if any source file is missing an SPDX Apache-2.0 header. Apache-2.0 asks
# that derivative works keep clear licensing; this keeps every file self-describing.
set -euo pipefail
cd "$(dirname "$0")/.."

needle="SPDX-License-Identifier: Apache-2.0"
missing=0

# Source we author (skip target/ and the vendored contract). Generated files
# (protoc-gen-go output, marked "Code generated ... DO NOT EDIT") are exempt.
while IFS= read -r -d '' f; do
  if head -n 3 "$f" | grep -q "Code generated"; then
    continue
  fi
  if ! head -n 5 "$f" | grep -q "$needle"; then
    echo "missing SPDX header: $f" >&2
    missing=1
  fi
done < <(find rust go scripts -type f \( -name '*.rs' -o -name '*.go' -o -name '*.sh' \) \
            -not -path '*/target/*' -print0)

if [ "$missing" -ne 0 ]; then
  echo "ERROR: add '// $needle' (or '# ...') to the files above." >&2
  exit 1
fi
echo "license headers OK"
