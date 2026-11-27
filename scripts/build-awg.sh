#!/usr/bin/env bash
# Build the Remnawave X AmneziaWG sidecar (userspace amneziawg-go).
#
# Combined work is AGPL-3.0-only. Runtime logic is ported from
# samur005/3s-ui wgserver (GPL-3.0). The engine is
# github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828 (MIT, WireGuard LLC),
# the same pin as 3s-ui. Do not copy LucX / PolyForm Noncommercial sources.
#
# Usage:
#   scripts/build-awg.sh [output-path]            # host platform
#   GOOS=linux GOARCH=arm64 scripts/build-awg.sh awg

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${1:-awg}"

cd "$root/sidecar/awg"
GOOS="${GOOS:-}" GOARCH="${GOARCH:-}" CGO_ENABLED="${CGO_ENABLED:-0}" \
    go build -trimpath -o "$out" ./cmd/awg

# If the caller passed a path outside the module, move the result there.
if [ "$out" != "awg" ] && [ ! -f "$out" ] && [ -f "$root/sidecar/awg/awg" ]; then
    mv "$root/sidecar/awg/awg" "$out"
fi

echo "built $out (amneziawg-go/v3 v3.1.20260828)"
