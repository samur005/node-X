#!/bin/sh
set -eu
# Binary is copied by the Dockerfile from the qwdtt build stage.
# This integration only installs iptables/iproute2 needed for the sidecar's
# own MASQUERADE NAT (direct egress on the node's default WAN).
mkdir -p /var/lib/remnawave/qwdtt
chmod 700 /var/lib/remnawave/qwdtt || true
echo "[integrations] qwdtt ready (sidecar NAT / direct egress)"
