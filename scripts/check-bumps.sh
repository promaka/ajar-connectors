#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Warn, never fail, when a released package changed on this branch but its
# version did not. Each connector, the SDK and the chart carry their own
# version, and merging a bump is what releases one; a change without a bump
# simply waits for the next one. That is sometimes intended (a refactor, a test),
# so this is advice for the reviewer, not a gate.
#
# Also warns when a version moved without a CHANGELOG entry for it (the release
# itself refuses that, see scripts/release-target.sh), and when shared code or
# the lock file changed, naming the connectors that only ship it once bumped.
# Changes to Markdown alone are ignored.
#
# Usage:  scripts/check-bumps.sh [base-ref]    (default: origin/main)
set -euo pipefail

base="${1:-origin/main}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mb="$(git merge-base "$base" HEAD)"

warned=0
warn() { # <file> <message>
  echo "::warning file=$1::$2"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- \`$1\`: $2" >>"$GITHUB_STEP_SUMMARY"
  warned=1
}

# Changed since the merge-base, ignoring Markdown.
changed() { # <path>...
  local files
  files="$(git diff --name-only "$mb" HEAD -- "$@")"
  [ -n "$files" ] && grep -qv '\.md$' <<<"$files"
}

# The first `version = "…"` / `version: …` line of a file, now or at the base.
version_now() { grep -m1 -E "$2" "$1" | sed -E 's/.*[=:] *"?([^"]+)"?.*/\1/'; }
version_base() { git show "$mb:$1" 2>/dev/null | grep -m1 -E "$2" | sed -E 's/.*[=:] *"?([^"]+)"?.*/\1/' || true; }

check() { # <label> <dir> <manifest> <version-regex> <changelog> <paths>...
  local label="$1" dir="$2" manifest="$3" re="$4" log="$5"
  shift 5
  changed "$@" || return 0
  local now was
  now="$(version_now "$manifest" "$re")"
  was="$(version_base "$manifest" "$re")"
  # New package, or one that only now stops inheriting a shared version.
  [ -n "$was" ] || return 0
  if [ "$now" = "$was" ]; then
    warn "$manifest" "$label changed but its version is still $now; bump it (and $log) to release the change"
  elif ! grep -qE "^## \[${now//./\\.}\]( |$)" "$log"; then
    warn "$log" "$label is now $now but $log has no entry for it"
  fi
}

# Every crate released on its own, from both workspaces: name, dir, deps.
released="$(for ws in rust/connectors rust/examples; do
  cargo metadata --no-deps --format-version 1 --manifest-path "$ws/Cargo.toml" \
    | jq -r --arg root "$root/" '
        .packages[] | select(.metadata.ajar.release == true)
        | [.name, (.manifest_path | ltrimstr($root) | rtrimstr("/Cargo.toml")),
           ([.dependencies[].name] | join(","))] | @tsv'
done)"

while IFS=$'\t' read -r pkg dir _deps; do
  [ -n "$pkg" ] || continue
  check "$pkg" "$dir" "$dir/Cargo.toml" '^version *=' "$dir/CHANGELOG.md" "$dir"
done <<<"$released"

check "the SDK" rust/ajar-connector rust/Cargo.toml '^version *=' CHANGELOG.md \
  rust/ajar-connector go python cpp vendor/contract
if grep -qE '^ +ajar\.release: *"?true"?' deploy/helm/connector/Chart.yaml; then
  check "the connector chart" deploy/helm/connector deploy/helm/connector/Chart.yaml \
    '^version:' deploy/helm/connector/CHANGELOG.md deploy/helm/connector
fi

# Shared code reaches a connector's image only when that connector is released.
for shared in rust/connectors/common:ajar-connector-common rust/connectors/sapient-wire:ajar-sapient-wire; do
  path="${shared%%:*}" crate="${shared#*:}"
  changed "$path" || continue
  users="$(awk -F'\t' -v c="$crate" '$3 ~ "(^|,)" c "(,|$)" { print $1 }' <<<"$released" | paste -sd' ' -)"
  [ -n "$users" ] && warn "$path" "$crate changed; it ships only in the connectors you bump: $users"
done
if changed rust/connectors/Cargo.lock rust/connectors/Cargo.toml; then
  warn rust/connectors/Cargo.lock "the shared dependencies changed; they ship only in the connectors you bump"
fi

[ "$warned" -eq 0 ] && echo "bump-check OK: every changed package has a new version"
exit 0
