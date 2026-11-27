// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Types and helpers are ported from samur005/3s-ui wgserver/config.go (GPL-3.0).
// JSON names follow the Remnawave X node contract (camelCase).
// Do not copy LucX / PolyForm Noncommercial sources.

package awg

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeAWG           = "awg"
	DefaultPort       = 51820
	DefaultMTU        = 1420
	DefaultKeepalive  = 25
	DefaultDNS        = "1.1.1.1, 8.8.8.8"
	DefaultAllowed    = "0.0.0.0/0, ::/0"
	DefaultAWGVersion = "2.0"
	SubnetPrefixMin   = 16
	SubnetPrefixMax   = 29
)

// Config is one AmneziaWG instance as sent by the panel (INodeAwgInstance).
type Config struct {
	ListenPort int    `json:"listenPort"`
	Listen     string `json:"listen,omitempty"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey,omitempty"`
	Subnet     string `json:"subnet"`
	MTU        int    `json:"mtu"`
	DNS        string `json:"dns"`
	Keepalive  int    `json:"keepalive"`
	AllowedIPs string `json:"allowedIps"`
	Endpoint   string `json:"endpoint,omitempty"`
	Version    string `json:"version"`
	Obfuscation
}

// Obfuscation is the AmneziaWG parameter set across all generations.
// Field names match 3s-ui / the node contract.
type Obfuscation struct {
	Jc                     int    `json:"jc"`
	Jmin                   int    `json:"jmin"`
	Jmax                   int    `json:"jmax"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"`
	S4                     int    `json:"s4"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1"`
	I2                     string `json:"i2"`
	I3                     string `json:"i3"`
	I4                     string `json:"i4"`
	I5                     string `json:"i5"`
	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition string `json:"contentPaddingAddition"`
	RekeyAfterTime         string `json:"rekeyAfterTime"`
	RekeyTimeout           string `json:"rekeyTimeout"`
	RejectAfterTime        string `json:"rejectAfterTime"`
	KeepaliveTimeout       string `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   string `json:"maxHandshakeAttempts"`
	RandomTrailers         bool   `json:"randomTrailers"`
	DisableCookies         bool   `json:"disableCookies"`
}

// Peer is what the node is allowed to see: public key, optional PSK, IPv4.
// Client private keys must never appear here.
type Peer struct {
	PublicKey    string `json:"publicKey"`
	PresharedKey string `json:"presharedKey,omitempty"`
	Address      string `json:"address"`
	Enabled      *bool  `json:"enabled,omitempty"`
}

func (p Peer) IsEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

// Request is the POST /node/awg/sync body (and the sidecar config file).
type Request struct {
	Enabled  bool    `json:"enabled"`
	Instance *Config `json:"instance"`
	Peers    []Peer  `json:"peers"`
}

// ServerAddr is the server's own tunnel address (first host of the subnet).
func (c Config) ServerAddr() (netip.Addr, error) {
	p, err := netip.ParsePrefix(c.Subnet)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid subnet %q", c.Subnet)
	}
	return p.Masked().Addr().Next(), nil
}

// ServerPrefix is ServerAddr with the subnet's prefix length.
func (c Config) ServerPrefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(c.Subnet)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid subnet %q", c.Subnet)
	}
	a, err := c.ServerAddr()
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, p.Bits()), nil
}

// EffectiveMTU is the configured MTU, or the default minus AmneziaWG padding.
func (c Config) EffectiveMTU() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return max(DefaultMTU-max(c.S4, 0), 1280)
}

func (c Config) normalizedVersion() string {
	v := strings.TrimSpace(c.Version)
	if v == "" {
		return DefaultAWGVersion
	}
	return v
}

func (c *Config) validate() error {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("port %d is out of range", c.ListenPort)
	}
	c.Subnet = strings.TrimSpace(c.Subnet)
	sp, err := netip.ParsePrefix(c.Subnet)
	if err != nil || !sp.Addr().Is4() {
		return fmt.Errorf("subnet %q must be an IPv4 network such as 10.8.1.0/24", c.Subnet)
	}
	if sp.Bits() < SubnetPrefixMin || sp.Bits() > SubnetPrefixMax {
		return fmt.Errorf("subnet %q: the prefix length must be between 16 and 29", c.Subnet)
	}
	c.Subnet = sp.Masked().String()
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 1500) {
		return fmt.Errorf("MTU %d must be 0 (automatic) or between 576 and 1500", c.MTU)
	}
	c.Version = c.normalizedVersion()
	if !ValidVersion(c.Version) {
		return fmt.Errorf("AmneziaWG version %q is not one of %s", c.Version, strings.Join(AWGVersions, ", "))
	}
	if !ValidKey(c.PrivateKey) {
		return fmt.Errorf("server private key: a WireGuard key is 32 bytes of base64")
	}
	c.Obfuscation = c.Obfuscation.Prune(c.Version)
	if err := c.Obfuscation.Validate(c.Version); err != nil {
		return err
	}
	return nil
}

func validatePeer(p Peer) error {
	if !ValidKey(p.PublicKey) {
		return fmt.Errorf("peer public key: a WireGuard key is 32 bytes of base64")
	}
	if p.PresharedKey != "" && !ValidKey(p.PresharedKey) {
		return fmt.Errorf("peer preshared key: a WireGuard key is 32 bytes of base64")
	}
	addr := strings.TrimSpace(strings.TrimSuffix(p.Address, "/32"))
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("peer address %q must be an IPv4 address", p.Address)
	}
	return nil
}
