// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.

package awg

import (
	"fmt"
	"net"
	"strings"
)

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if op, ok := err.(*net.OpError); ok {
		return isAddrInUse(op.Err)
	}
	s := err.Error()
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "only one usage of each socket address")
}

// checkUDPPortFree reports a clear error if the UDP port is already taken.
// The sidecar does not pick the next port: the panel owns that choice.
func checkUDPPortFree(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is out of range", port)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("UDP port %d is already in use", port)
		}
		return fmt.Errorf("UDP port %d: %w", port, err)
	}
	_ = conn.Close()
	conn6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: port})
	if err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("UDP port %d is already in use", port)
		}
		// IPv6 may be disabled on the host; that is not a port conflict.
		return nil
	}
	_ = conn6.Close()
	return nil
}
