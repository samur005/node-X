#!/bin/sh
# Binary is copied by the Dockerfile from the awg build stage.

set -eu

mkdir -p /var/lib/remnawave/awg
chmod 700 /var/lib/remnawave/awg || true
echo "[integrations] awg ready (sidecar NAT / rxawg0)"
