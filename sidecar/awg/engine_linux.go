//go:build linux

// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Ported from samur005/3s-ui wgserver/engine_linux.go (GPL-3.0):
// CreateTUN, device.IpcSet, peer reconcile without dropping sessions,
// ensureNAT (iptables MASQUERADE + ip_forward). Traffic does not enter Xray.
// Do not copy LucX / PolyForm Noncommercial sources.

package awg

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// EngineSupported is true where the server device can be created.
func EngineSupported() bool { return true }

type running struct {
	iface string
	fp    string
	dev   *device.Device
	peers map[string]string // public key -> peer fingerprint
	cfg   Config
}

// Server owns the single v1 instance on this node.
type Server struct {
	mu      sync.Mutex
	run     *running
	lastErr string
	enabled bool
}

func engineLogger() *device.Logger {
	return &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if strings.Contains(msg, "no known endpoint for peer") {
				return
			}
			log.Printf("awg: %s", msg)
		},
	}
}

func ipRun(args ...string) error {
	out, err := exec.CommandContext(context.Background(), "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func succeeds(name string, args ...string) bool {
	return exec.CommandContext(context.Background(), name, args...).Run() == nil
}

func runQuiet(name string, args ...string) {
	if out, err := exec.CommandContext(context.Background(), name, args...).CombinedOutput(); err != nil {
		log.Printf("awg: %s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func haveIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func writeProc(path, value string) {
	if err := os.WriteFile("/proc/sys/"+path, []byte(value), 0o644); err != nil {
		log.Printf("awg: setting %s: %v", path, err)
	}
}

func ensureIptables(table string, insert bool, chain string, rule ...string) {
	base := []string{}
	if table != "" {
		base = append(base, "-t", table)
	}
	if !haveIptables() {
		return
	}
	if succeeds("iptables", append(append(append([]string{}, base...), "-C", chain), rule...)...) {
		return
	}
	op := []string{"-A", chain}
	if insert {
		op = []string{"-I", chain, "1"}
	}
	runQuiet("iptables", append(append(append([]string{}, base...), op...), rule...)...)
}

func deleteIptables(table, chain string, rule ...string) {
	base := []string{}
	if table != "" {
		base = append(base, "-t", table)
	}
	for i := 0; i < 4; i++ {
		if !succeeds("iptables", append(append(append([]string{}, base...), "-D", chain), rule...)...) {
			return
		}
	}
}

func ensureForward(iface string) {
	writeProc("net/ipv4/ip_forward", "1")
	if !haveIptables() {
		return
	}
	ensureIptables("", true, "FORWARD", "-i", iface, "-j", "ACCEPT")
	ensureIptables("", true, "FORWARD", "-o", iface, "-j", "ACCEPT")
}

// ensureNAT masquerades the client subnet out the node's WAN, excluding the
// tunnel iface itself. Same as 3s-ui when RouteThroughCore is off.
func ensureNAT(cfg Config, iface string) error {
	if !haveIptables() {
		return fmt.Errorf("iptables is not installed: the node needs it to forward and NAT client traffic")
	}
	ensureForward(iface)
	ensureIptables("nat", false, "POSTROUTING", "-s", cfg.Subnet, "!", "-o", iface, "-j", "MASQUERADE")
	return nil
}

func clearNetwork(iface string, cfg Config) {
	deleteIptables("", "FORWARD", "-i", iface, "-j", "ACCEPT")
	deleteIptables("", "FORWARD", "-o", iface, "-j", "ACCEPT")
	if cfg.Subnet != "" {
		deleteIptables("nat", "POSTROUTING", "-s", cfg.Subnet, "!", "-o", iface, "-j", "MASQUERADE")
	}
	if succeeds("ip", "link", "show", iface) {
		runQuiet("ip", "link", "delete", iface)
	}
}

func startDevice(cfg Config) (*running, error) {
	if err := checkUDPPortFree(cfg.ListenPort); err != nil {
		return nil, err
	}
	// A leftover rxawg0 from a previous crash would block CreateTUN.
	if succeeds("ip", "link", "show", IfaceName) {
		runQuiet("ip", "link", "delete", IfaceName)
	}
	conf, err := deviceConfig(cfg)
	if err != nil {
		return nil, err
	}
	tdev, err := tun.CreateTUN(IfaceName, cfg.EffectiveMTU())
	if err != nil {
		return nil, fmt.Errorf("creating the network device %s: %w (needs NET_ADMIN and /dev/net/tun)", IfaceName, err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), engineLogger())
	if err := dev.IpcSet(conf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configuring the server: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bringing the server up: %w", err)
	}
	prefix, err := cfg.ServerPrefix()
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := ipRun("addr", "replace", prefix.String(), "dev", IfaceName); err != nil {
		dev.Close()
		return nil, fmt.Errorf("addressing %s: %w", IfaceName, err)
	}
	if err := ipRun("link", "set", "dev", IfaceName, "mtu", strconv.Itoa(cfg.EffectiveMTU()), "up"); err != nil {
		dev.Close()
		return nil, fmt.Errorf("raising %s: %w", IfaceName, err)
	}
	log.Printf("awg: listening on UDP %d (%s, version %s)", cfg.ListenPort, IfaceName, cfg.Version)
	return &running{iface: IfaceName, fp: deviceFingerprint(cfg), dev: dev, peers: map[string]string{}, cfg: cfg}, nil
}

// syncDevicePeers changes only what differs: peers that left are removed,
// new or changed ones are set. Peers that stay keep their sessions.
func syncDevicePeers(r *running, active []Peer) error {
	desired := map[string]Peer{}
	for _, p := range active {
		desired[p.PublicKey] = p
	}
	var b strings.Builder
	for pub := range r.peers {
		if _, ok := desired[pub]; !ok {
			s, err := peerRemove(pub)
			if err != nil {
				return err
			}
			b.WriteString(s)
		}
	}
	for pub, p := range desired {
		if r.peers[pub] == peerFP(p) {
			continue
		}
		s, err := peerAdd(p)
		if err != nil {
			return err
		}
		b.WriteString(s)
	}
	if b.Len() == 0 {
		return nil
	}
	if err := r.dev.IpcSet(b.String()); err != nil {
		return err
	}
	r.peers = map[string]string{}
	for pub, p := range desired {
		r.peers[pub] = peerFP(p)
	}
	return nil
}

func activePeers(peers []Peer) ([]Peer, error) {
	var out []Peer
	for _, p := range peers {
		if !p.IsEnabled() {
			continue
		}
		if err := validatePeer(p); err != nil {
			return nil, err
		}
		p.Address = strings.TrimSpace(strings.TrimSuffix(p.Address, "/32"))
		out = append(out, p)
	}
	return out, nil
}

func (s *Server) stopLocked() {
	if s.run == nil {
		return
	}
	if s.run.dev != nil {
		s.run.dev.Close()
	}
	clearNetwork(s.run.iface, s.run.cfg)
	s.run = nil
}

// Apply brings the single instance in line with the request. It is cheap when
// only peers changed (sessions stay up). A device fingerprint change rebuilds
// the interface.
func (s *Server) Apply(req Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = req.Enabled
	if !req.Enabled || req.Instance == nil {
		s.stopLocked()
		s.lastErr = ""
		return nil
	}
	cfg := *req.Instance
	if err := cfg.validate(); err != nil {
		s.lastErr = err.Error()
		return err
	}
	active, err := activePeers(req.Peers)
	if err != nil {
		s.lastErr = err.Error()
		return err
	}
	fp := deviceFingerprint(cfg)
	if s.run != nil && s.run.fp != fp {
		s.stopLocked()
	}
	if s.run == nil {
		r, err := startDevice(cfg)
		if err != nil {
			s.lastErr = err.Error()
			return err
		}
		s.run = r
	}
	s.run.cfg = cfg
	if err := syncDevicePeers(s.run, active); err != nil {
		s.lastErr = "peers: " + err.Error()
		return err
	}
	if err := ensureNAT(cfg, s.run.iface); err != nil {
		s.lastErr = err.Error()
		return err
	}
	s.lastErr = ""
	return nil
}

// Shutdown stops the device and removes NAT rules.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	s.stopLocked()
	s.lastErr = ""
}

func (s *Server) snapshot() (Status, *running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Supported: true,
		Enabled:   s.enabled,
		Iface:     IfaceName,
		Egress:    "sidecar-nat",
		Error:     s.lastErr,
	}
	if s.run != nil {
		st.Running = true
		st.Iface = s.run.iface
		st.Peers = len(s.run.peers)
		st.Version = s.run.cfg.Version
	}
	return st, s.run
}

// Status snapshots the instance. Online is handshakes in the last 3 minutes.
func (s *Server) Status() Status {
	st, r := s.snapshot()
	if r == nil || r.dev == nil {
		return st
	}
	text, err := r.dev.IpcGet()
	if err != nil {
		return st
	}
	now := time.Now().Unix()
	for _, ps := range parseStats(text) {
		if ps.LastHandshake > 0 && now-ps.LastHandshake < 180 {
			st.Online++
		}
	}
	return st
}
