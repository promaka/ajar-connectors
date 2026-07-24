#!/usr/bin/env sh
# Cut a versioned, signed connector image to GHCR. This repo is PUBLIC and must
# never be git-pushed; publishing a compiled *image* is fine — the source stays
# local. No CI does this (repo isn't on GitHub CI), so run it by hand on a release.
#
# Prereqs (one-time): `docker login ghcr.io -u <you>` (token w/ write:packages),
# and `cosign` on PATH.
#
# Usage (from repo root):
#   ./deploy/release.sh tak-egress v0.1.0            # a production connector
#   ./deploy/release.sh synthetic-radar v0.1.0 rust/examples   # an example
set -eu

NAME="${1:?usage: ./deploy/release.sh <connector> vX.Y.Z [wsdir] [cargo-pkg]}"
VERSION="${2:?usage: ./deploy/release.sh <connector> vX.Y.Z [wsdir] [cargo-pkg]}"
WSDIR="${3:-rust/connectors}"

# The published image keeps the short name (ajar-connector-<name>), but the cargo
# package differs by workspace: production connectors are crates named
# `ajar-<name>`, while the examples keep their bare name. Override with a 4th arg
# if a crate ever breaks the convention.
if [ "$#" -ge 4 ]; then
  PKG="$4"
else
  case "$WSDIR" in
  *connectors) PKG="ajar-${NAME}" ;;
  *) PKG="${NAME}" ;;
  esac
fi
IMAGE="ghcr.io/promaka/ajar-connector-${NAME}"

echo "building + pushing $IMAGE:$VERSION (multi-arch, $WSDIR -p $PKG)"
docker buildx build -f deploy/docker/Dockerfile.build \
  --platform linux/amd64,linux/arm64 \
  --build-arg WSDIR="$WSDIR" --build-arg PKG="$PKG" \
  -t "$IMAGE:$VERSION" -t "$IMAGE:latest" \
  --metadata-file /tmp/conn-meta.json --push .

DIGEST=$(jq -r '."containerimage.digest"' /tmp/conn-meta.json)
echo "signing $IMAGE@$DIGEST"
cosign sign --yes "$IMAGE@$DIGEST"

echo "done: $IMAGE:$VERSION signed @ $DIGEST  (do NOT git-push this repo)"
