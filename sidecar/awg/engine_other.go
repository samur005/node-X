//go:build !linux

// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.

package awg

import "fmt"

func EngineSupported() bool { return false }

// Server is a stub on non-Linux platforms.
type Server struct {
	enabled bool
	lastErr string
}

func (s *Server) Apply(req Request) error {
	s.enabled = req.Enabled
	s.lastErr = "AWG is only supported on Linux"
	return fmt.Errorf("%s", s.lastErr)
}

func (s *Server) Shutdown() {
	s.enabled = false
}

func (s *Server) Status() Status {
	return Status{
		Supported: false,
		Enabled:   s.enabled,
		Iface:     IfaceName,
		Egress:    "sidecar-nat",
		Error:     s.lastErr,
	}
}
