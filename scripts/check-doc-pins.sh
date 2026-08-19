#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every install instruction must pin the version being released. A vendor who
# follows a stale pin gets an SDK from an earlier ontology and their events are
# silently discarded downstream, so this is checked before a release is cut.
#
# Usage:  scripts/check-doc-pins.sh [version]   (default: rust/connectors/Cargo.toml)
set -euo pipefail
want="${1:-$(grep -m1 '^version' rust/connectors/Cargo.toml | cut -d'"' -f2)}"
docs=(README.md ONBOARDING.md COMPATIBILITY.md CONNECTOR_BRIEF.md)

bad=0
for f in "${docs[@]}"; do
  # Any vN.N.N that is not the release version, ignoring the changelog-style
  # history lines that legitimately name older releases.
  while IFS=: read -r line text; do
    [ -n "$line" ] || continue
    echo "  $f:$line: $(echo "$text" | sed 's/^ *//' | cut -c1-100)"
    bad=1
  done < <(grep -nE "v[0-9]+\.[0-9]+\.[0-9]+" "$f" | grep -vE "v${want//./\\.}([^0-9]|$)" || true)
done

if [ "$bad" -ne 0 ]; then
  echo "::error::the lines above pin a version other than $want; update them before releasing"
  exit 1
fi
echo "doc pins OK: every documented version is $want"
