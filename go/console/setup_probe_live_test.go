package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wendylabsinc/wendy/go/internal/shared/ble/central"
	"github.com/wendylabsinc/wendy/go/internal/shared/ble/scan"
)

// Requires an unenrolled test board. It sends no configuration or credentials.
// WENDY_SETUP_LIVE_NAME=esp-setup-test go test -run TestLiveSetupRecovery -v
func TestLiveSetupRecovery(t *testing.T) {
	name := os.Getenv("WENDY_SETUP_LIVE_NAME")
	if name == "" {
		t.Skip("set WENDY_SETUP_LIVE_NAME to test an unenrolled board")
	}
	discover := func() scan.BLEDeviceInfo {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := scan.DiscoverBluetoothContinuous(ctx, scan.Options{
			Services: []string{"7565e9eb-4c20-4b67-9272-d708b397b632"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var found map[string]scan.BLEDeviceInfo = make(map[string]scan.BLEDeviceInfo)
		for devices := range stream {
			for _, d := range devices {
				if d.Name == name || (len(d.Name) >= 8 && strings.HasPrefix(name, d.Name)) {
					found[d.Address] = d
				}
			}
		}
		if len(found) != 1 {
			t.Fatalf("expected one setup advertiser named %q, found %d", name, len(found))
		}
		for _, d := range found {
			return d
		}
		panic("unreachable")
	}
	d := discover()
	conn, err := central.Connect(d.Address, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.OpenL2CAP(129, 5); err == nil {
		t.Fatal("setup board accepted a mesh channel")
	}
	if err := conn.OpenL2CAP(131, 10); err != nil {
		t.Fatal(err)
	}
	wire := central.NewL2CAPStream(conn)
	wire.SetReadDeadline(time.Now().Add(22 * time.Second))
	start := time.Now()
	var b [1]byte
	_, err = wire.Read(b[:]) // Deliberately never send the setup hello.
	if err == nil {
		t.Fatal("idle setup channel unexpectedly returned data")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("firmware did not release the idle channel: %v", err)
	}
	t.Logf("idle setup client released after %s", time.Since(start).Round(time.Millisecond))
	// Do not close the central connection before scanning: the board itself
	// must release GAP and advertise again, not just close the L2CAP channel.
	again := discover()
	if again.Address != d.Address {
		t.Fatal("setup address changed across a session retry")
	}
	t.Log("board resumed advertising without the client disconnecting")
}
