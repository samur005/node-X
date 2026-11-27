# Remnawave X AmneziaWG sidecar

Userspace AmneziaWG server that runs next to Xray inside the `node-x` image.
It is not an Xray inbound. v1 egress is NAT MASQUERADE from the client subnet
to the node's WAN (the 3s-ui mode with `RouteThroughCore` off).

Combined Remnawave X work is **AGPL-3.0-only**. Runtime logic is ported from
[samur005/3s-ui](https://github.com/samur005/3s-ui) `wgserver` (GPL-3.0).
Do not copy LucX / PolyForm Noncommercial sources.

The engine is [`github.com/amnezia-vpn/amneziawg-go/v3`](https://github.com/amnezia-vpn/amneziawg-go)
**v3.1.20260828** (same pin as 3s-ui). Its license is **MIT** (Copyright (C)
2017-2025 WireGuard LLC), re-checked on 27 November 2026. It is pulled at
build time, not vendored in this repository.

## Contract

The node agent writes `/var/lib/remnawave/awg/config.json` (the
`POST /node/awg/sync` body) and starts `/usr/local/bin/awg`. `SIGHUP` reloads
the file and reconciles peers without dropping unchanged sessions. `SIGTERM`
closes the device and removes NAT rules. Live status is written to
`status.json` (`running`, `iface`, `peers`, `online`).

The payload contains the **server** private key and **peer public** keys, plus
PSK and the peer IPv4 `/32`. Client private keys must never appear.

## Host resources

The remnanode container already has `NET_ADMIN`, `/dev/net/tun` and
`network_mode: host`. This sidecar creates one additional TUN named **`rxawg0`**.
That prefix is Remnawave X's own so it does not collide with 3s-ui (`s3awg…`)
or a standalone amnezia-wireguard/awg2 (`awg0`, `wg0`) on the same host
(especially NL).

Default listen port is 51820. If the port is already taken, the sidecar fails
with a clear error and does not pick the next port — the panel owns that choice.

v1 is one instance per node. iptables and iproute2 are already in the node
image for qWDTT; the `awg` integration also lists them so an AWG-only build
still works.
