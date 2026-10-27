#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Resolve a per-package release tag to what it builds, and refuse a tag that
# cannot produce an honest release. Each connector is versioned on its own:
#
#   <name>-vX.Y.Z    the crate ajar-<name> (or <name> in rust/examples) carrying
#                    [package.metadata.ajar] release = true at version X.Y.Z
#   chart-vX.Y.Z     the connector Helm chart at Chart.yaml version X.Y.Z, when
#                    its annotation ajar.release is "true"
#
# The tag must match the version in the manifest, and the package's CHANGELOG.md
# must have an entry for it, or nothing is published. On success it prints
# key=value lines (name, kind, version, wsdir, pkg, dir, image), which the
# release workflow appends to $GITHUB_OUTPUT.
#
# Usage:  scripts/release-target.sh <tag>      e.g. scripts/release-target.sh adsb-v0.6.6
set -euo pipefail

tag="${1:-}"
if [[ ! "$tag" =~ ^([a-z0-9][a-z0-9-]*)-v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]]; then
  echo "::error::'$tag' is not a release tag; expected <name>-vX.Y.Z, e.g. adsb-v0.6.6" >&2
  exit 1
fi
name="${BASH_REMATCH[1]}"
want="${BASH_REMATCH[2]}"
root="$(cd "$(dirname "$0")/.." && pwd)"

changelog_has() { # <changelog> <version>
  grep -qE "^## \[${2//./\\.}\]( |$)" "$1"
}

if [ "$name" = chart ]; then
  dir="deploy/helm/connector"
  if ! grep -qE '^ +ajar\.release: *"?true"?' "$root/$dir/Chart.yaml"; then
    echo "::error::the chart is not released on its own; set the annotation ajar.release: \"true\" in $dir/Chart.yaml" >&2
    exit 1
  fi
  ver="$(grep -m1 '^version:' "$root/$dir/Chart.yaml" | awk '{print $2}')"
  kind=chart wsdir="" pkg="" image=false
else
  # The released crates of both workspaces that ship binaries, by crate name.
  found=""
  for ws in rust/connectors rust/examples; do
    found="$(cargo metadata --no-deps --format-version 1 \
        --manifest-path "$root/$ws/Cargo.toml" \
      | jq -r --arg a "ajar-$name" --arg b "$name" --arg ws "$ws" --arg root "$root/" '
          .packages[]
          | select(.name == $a or .name == $b)
          | [.name, .version, (.manifest_path | ltrimstr($root) | rtrimstr("/Cargo.toml")),
             (.metadata.ajar.release == true), (.metadata.ajar.image != false), $ws]
          | @tsv')"
    [ -n "$found" ] && break
  done
  if [ -z "$found" ]; then
    echo "::error::no crate ajar-$name or $name in rust/connectors or rust/examples" >&2
    exit 1
  fi
  IFS=$'\t' read -r pkg ver dir release image wsdir <<<"$found"
  if [ "$release" != true ]; then
    echo "::error::$pkg is not released on its own; set [package.metadata.ajar] release = true in $dir/Cargo.toml" >&2
    exit 1
  fi
  kind=crate
fi

if [ "$ver" != "$want" ]; then
  echo "::error::tag $tag does not match $dir version $ver; bump the version or fix the tag" >&2
  exit 1
fi
if ! changelog_has "$root/$dir/CHANGELOG.md" "$want"; then
  echo "::error::$dir/CHANGELOG.md has no entry for $want; write one before tagging" >&2
  exit 1
fi

cat <<EOF
name=$name
kind=$kind
version=$ver
wsdir=$wsdir
pkg=$pkg
dir=$dir
image=$image
EOF
