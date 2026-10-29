#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Print the release tag of every package whose current version is not tagged
# yet, one per line: each connector or tool carrying
# [package.metadata.ajar] release = true (as <name>-vX.Y.Z) and the connector
# chart when its Chart.yaml annotation ajar.release is "true" (as chart-vX.Y.Z).
# Run on main after a merge, it turns a merged version bump into the tags to
# release, which is what makes merging the release.
#
# It compares against the tags, not against the previous commit, so a run that
# stopped before tagging (cancelled, or refused by the guard and fixed in a
# later PR) is picked up by the next run.
#
# A version below the package's highest released one is refused, and nothing is
# printed, so a downgrade is fixed before anything ships. Pre-release suffixes
# are ignored for that comparison (1.0.0-rc.1 counts as 1.0.0).
#
# Usage:  scripts/release-tags.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

core() { echo "${1%%-*}"; } # 1.2.3-rc.1 -> 1.2.3

# The package's highest released X.Y.Z, from its <name>-vX.Y.Z tags, or nothing.
highest() { # <tag-name>
  git tag -l "$1-v*" | sed -nE "s/^$1-v([0-9]+\.[0-9]+\.[0-9]+)(-.*)?$/\1/p" | sort -V | tail -1
}

tags=()
failed=0
consider() { # <tag-name> <version> <manifest>
  local name="$1" now="$2" top
  git rev-parse -q --verify "refs/tags/$name-v$now" >/dev/null && return 0
  top="$(highest "$name")"
  if [ -n "$top" ] && [ "$(core "$now")" != "$top" ] &&
    [ "$(printf '%s\n%s\n' "$(core "$now")" "$top" | sort -V | tail -1)" = "$top" ]; then
    echo "::error file=$3::$name is at $now, below its released $top; versions only go up" >&2
    failed=1
    return 0
  fi
  tags+=("$name-v$now")
}

while IFS=$'\t' read -r name version manifest; do
  consider "$name" "$version" "$manifest"
done < <(for ws in rust/connectors rust/examples; do
  cargo metadata --no-deps --format-version 1 --manifest-path "$ws/Cargo.toml" \
    | jq -r --arg root "$root/" '
        .packages[] | select(.metadata.ajar.release == true)
        | [(.name | ltrimstr("ajar-")), .version, (.manifest_path | ltrimstr($root))] | @tsv'
done)
chart=deploy/helm/connector/Chart.yaml
if grep -qE '^ +ajar\.release: *"?true"?' "$chart"; then
  consider chart "$(grep -m1 '^version:' "$chart" | awk '{print $2}')" "$chart"
fi

[ "$failed" -eq 0 ] || exit 1
[ "${#tags[@]}" -eq 0 ] || printf '%s\n' "${tags[@]}"
