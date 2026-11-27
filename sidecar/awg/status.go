// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Ported from samur005/3s-ui wgserver/status.go and stats.go (GPL-3.0).
// v1 status is running, iface, peers and online — not per-client counters.

package awg

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// Status is the live state of the AWG sidecar.
type Status struct {
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Iface     string `json:"iface"`
	Peers     int    `json:"peers"`
	Online    int    `json:"online"`
	Version   string `json:"version,omitempty"`
	Egress    string `json:"egress"`
	Error     string `json:"error,omitempty"`
}

// PeerStat is the engine's counters for one peer. Not exposed in v1 status
// beyond the online count (handshake in the last three minutes).
type PeerStat struct {
	PublicKey     string
	Rx, Tx        int64
	LastHandshake int64 // unix seconds, 0 = never
}

func parseStats(text string) []PeerStat {
	var out []PeerStat
	var cur *PeerStat
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			raw, err := hex.DecodeString(v)
			if err != nil {
				cur = nil
				continue
			}
			out = append(out, PeerStat{PublicKey: base64.StdEncoding.EncodeToString(raw)})
			cur = &out[len(out)-1]
		case "rx_bytes":
			if cur != nil {
				cur.Rx, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.Tx, _ = strconv.ParseInt(v, 10, 64)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshake, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return out
}
