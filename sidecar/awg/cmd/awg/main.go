// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// Remnawave X AmneziaWG sidecar: userspace amneziawg-go, supervised by node-X.
// Runtime logic is ported from samur005/3s-ui wgserver (GPL-3.0).
// The engine is github.com/amnezia-vpn/amneziawg-go/v3 (MIT, WireGuard LLC),
// pinned to v3.1.20260828 (same as 3s-ui).

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	awg "github.com/samur005/node-X/sidecar/awg"
)

func main() {
	var (
		configPath = flag.String("config", "/var/lib/remnawave/awg/config.json", "path to the sync payload JSON")
		statusPath = flag.String("status", "/var/lib/remnawave/awg/status.json", "path to write live status JSON")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("awg: ")

	server := &awg.Server{}
	defer server.Shutdown()

	apply := func() {
		req, err := loadRequest(*configPath)
		if err != nil {
			log.Printf("reading config: %v", err)
			writeStatus(*statusPath, awg.Status{
				Supported: awg.EngineSupported(),
				Iface:     awg.IfaceName,
				Egress:    "sidecar-nat",
				Error:     err.Error(),
			})
			return
		}
		if err := server.Apply(req); err != nil {
			log.Printf("apply: %v", err)
		}
		writeStatus(*statusPath, server.Status())
	}

	apply()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				log.Printf("SIGHUP: reloading %s", *configPath)
				apply()
				continue
			}
			log.Printf("shutting down (%s)", sig)
			server.Shutdown()
			writeStatus(*statusPath, server.Status())
			return
		case <-ticker.C:
			writeStatus(*statusPath, server.Status())
		}
	}
}

func loadRequest(path string) (awg.Request, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return awg.Request{}, err
	}
	var req awg.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return awg.Request{}, fmt.Errorf("invalid config JSON: %w", err)
	}
	return req, nil
}

func writeStatus(path string, st awg.Status) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("status dir: %v", err)
		return
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Printf("status json: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		log.Printf("status write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("status rename: %v", err)
	}
}
