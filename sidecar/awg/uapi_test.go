// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Ported test ideas from samur005/3s-ui wgserver (GPL-3.0).
// Keys in this file are 32-byte placeholders, not real credentials.

package awg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func placeholderKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func testConfig(version string) Config {
	o := Generate(version)
	return Config{
		ListenPort:  51820,
		PrivateKey:  placeholderKey(0x11),
		Subnet:      "10.8.1.0/24",
		Version:     version,
		Obfuscation: o,
	}
}

func TestDeviceConfigIncludesVersionFields(t *testing.T) {
	cfg := testConfig("2.0")
	text, err := deviceConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "listen_port=51820", "jc=", "s1=", "s3=", "s4=", "h1="} {
		if !strings.Contains(text, want) {
			t.Errorf("2.0 config missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, "header_protection_key=") {
		t.Errorf("2.0 must not write 3.0 fields")
	}

	cfg15 := testConfig("1.5")
	text15, err := deviceConfig(cfg15)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text15, "s3=") {
		t.Errorf("1.5 must not write s3: %s", text15)
	}
	if !strings.Contains(text15, "i1=") {
		t.Errorf("1.5 should write i1")
	}

	cfg30 := testConfig("3.0")
	text30, err := deviceConfig(cfg30)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text30, "header_protection_key=") {
		t.Errorf("3.0 must write header protection key")
	}
}

func TestPeerAddHasNoPrivateKeyAndUsesSlash32(t *testing.T) {
	text, err := peerAdd(Peer{
		PublicKey:    placeholderKey(0x22),
		PresharedKey: placeholderKey(0x33),
		Address:      "10.8.1.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(text), "private") {
		t.Errorf("peer UAPI must not mention a private key: %s", text)
	}
	if !strings.Contains(text, "allowed_ip=10.8.1.2/32") {
		t.Errorf("expected /32 allowed_ip, got %s", text)
	}
	if !strings.Contains(text, "preshared_key=") {
		t.Errorf("expected preshared_key")
	}
}

func TestDeviceFingerprintIgnoresPeerOnlyFields(t *testing.T) {
	a := testConfig("2.0")
	b := a
	b.DNS = "8.8.8.8"
	b.Endpoint = "example.com:51820"
	b.Keepalive = 25
	if deviceFingerprint(a) != deviceFingerprint(b) {
		t.Error("DNS/endpoint/keepalive must not rebuild the device")
	}
	b.ListenPort = 51821
	if deviceFingerprint(a) == deviceFingerprint(b) {
		t.Error("listen port change must rebuild the device")
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := testConfig("2.0")
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.ListenPort = 70000
	if err := bad.validate(); err == nil {
		t.Error("port 70000 should fail")
	}
	bad = cfg
	bad.Subnet = "10.8.0.0/8"
	if err := bad.validate(); err == nil {
		t.Error("prefix /8 should fail")
	}
	bad = cfg
	bad.Version = "4.0"
	if err := bad.validate(); err == nil {
		t.Error("unknown version should fail")
	}
}

func TestIfaceNameDoesNotCollide(t *testing.T) {
	if IfaceName != "rxawg0" {
		t.Errorf("v1 iface must be rxawg0, got %q", IfaceName)
	}
	for _, reserved := range []string{"s3awg", "s3wg", "awg0", "wg0", "wdtt0", "wdttraw0"} {
		if IfaceName == reserved || strings.HasPrefix(IfaceName, "s3awg") || strings.HasPrefix(IfaceName, "s3wg") {
			t.Errorf("iface %q collides with reserved name %q", IfaceName, reserved)
		}
		if IfaceName == reserved {
			t.Errorf("iface collides with %q", reserved)
		}
	}
}

func TestParseStatsOnline(t *testing.T) {
	pubHex, err := keyHex(placeholderKey(0x22))
	if err != nil {
		t.Fatal(err)
	}
	got := parseStats("private_key=aa\nlisten_port=1\npublic_key=" + pubHex + "\nlast_handshake_time_sec=1700000000\ntx_bytes=10\nrx_bytes=20\nerrno=0\n")
	if len(got) != 1 || got[0].PublicKey != placeholderKey(0x22) || got[0].LastHandshake != 1700000000 || got[0].Rx != 20 {
		t.Fatalf("unexpected stats: %+v", got)
	}
}

func TestRequestJSONIgnoresClientPrivateKey(t *testing.T) {
	raw := []byte(`{"enabled":true,"instance":null,"peers":[{"publicKey":"` + placeholderKey(0x22) + `","privateKey":"` + placeholderKey(0x99) + `","address":"10.8.1.2"}]}`)
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Peers) != 1 {
		t.Fatalf("peers: %+v", req.Peers)
	}
	enc, _ := json.Marshal(req.Peers[0])
	if strings.Contains(string(enc), "privateKey") || strings.Contains(string(enc), placeholderKey(0x99)) {
		t.Errorf("client private key leaked into the peer struct: %s", enc)
	}
}
