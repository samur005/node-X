// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Naming idea follows samur005/3s-ui wgserver/names.go (GPL-3.0), but the
// prefix is Remnawave X's own so it does not collide with 3s-ui (s3awg*)
// or a standalone amnezia-wireguard/awg2 (awg0, wg0) on the same host.

package awg

// IfacePrefix is the Remnawave X TUN name prefix. Linux limits names to 15 bytes.
const IfacePrefix = "rxawg"

// IfaceName is the v1 interface (one instance per node).
const IfaceName = IfacePrefix + "0"
