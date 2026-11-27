// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Ported from samur005/3s-ui wgserver/keys.go (GPL-3.0).
// Do not copy LucX / PolyForm Noncommercial sources.

package awg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func decodeKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("a WireGuard key is 32 bytes of base64")
	}
	return raw, nil
}

// keyHex converts a base64 key to the hex the engine's config interface takes.
func keyHex(s string) (string, error) {
	raw, err := decodeKey(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ValidKey reports whether s is a 32-byte base64 key.
func ValidKey(s string) bool { _, err := decodeKey(s); return err == nil }
