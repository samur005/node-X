#!/usr/bin/env bash
# Builds the qWDTT server sidecar that Remnawave Node-X supervises.
#
# The binary is the `./server` command of SpaceNeuroX/proxy-turn-vk-android
# (GPL-3.0), pinned to a commit, plus scripts/patches/qwdtt-subnet.patch
# (moves the tunnel subnet 10.66.0.0/16 -> 10.68.0.0/16 so it cannot clash
# with a wdtt server on the same host). The pin, patch and build flags follow
# samur005/3s-ui scripts/build-qwdtt.sh (GPL-3.0).
#
# Usage:
#   scripts/build-qwdtt.sh [output-path]            # host platform
#   GOOS=linux GOARCH=arm64 scripts/build-qwdtt.sh qwdtt
set -euo pipefail

QWDTT_REPO="${QWDTT_REPO:-https://github.com/SpaceNeuroX/proxy-turn-vk-android.git}"
# v1.4.4
QWDTT_REF="${QWDTT_REF:-a296c57eaba69bb9479a24f9157856490890e47d}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-qwdtt}"
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git init -q "$work/src"
git -C "$work/src" remote add origin "$QWDTT_REPO"
git -C "$work/src" fetch -q --depth=1 origin "$QWDTT_REF"
git -C "$work/src" checkout -q FETCH_HEAD
git -C "$work/src" apply --whitespace=nowarn "$here/patches/qwdtt-subnet.patch"

(
	cd "$work/src"
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$out" ./server
)
chmod 755 "$out"
echo "built $out ($(git -C "$work/src" rev-parse --short HEAD) + qwdtt-subnet.patch)"
