package awg

import (
	"net"
	"strings"
	"testing"
)

func TestCheckUDPPortFreeAndConflict(t *testing.T) {
	if err := checkUDPPortFree(0); err == nil {
		t.Error("port 0 should be out of range")
	}
	if err := checkUDPPortFree(70000); err == nil {
		t.Error("port 70000 should be out of range")
	}

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Skip("cannot bind a UDP port in this environment:", err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	err = checkUDPPortFree(port)
	ln.Close()
	if err == nil {
		t.Fatalf("expected UDP port %d to be reported in use", port)
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected a clear in-use error, got %v", err)
	}
	if err := checkUDPPortFree(port); err != nil {
		t.Fatalf("port should be free after close: %v", err)
	}
}
