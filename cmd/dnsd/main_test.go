package main

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestHelperMain runs the real main() when re-executed by
// TestDNSBindFailureExits; it is a no-op in a normal test run.
func TestHelperMain(t *testing.T) {
	if os.Getenv("DNSD_TEST_RUN_MAIN") != "1" {
		t.Skip("helper process")
	}
	os.Args = []string{"dnsd"}
	main()
}

// A DNS port already held by another process (dnsmasq on het, 2026-09-17)
// must make dnsd exit non-zero, not keep running without DNS.
func TestDNSBindFailureExits(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	cmd.Env = append(os.Environ(),
		"DNSD_TEST_RUN_MAIN=1",
		"DNSD_LISTEN=127.0.0.1:0",
		"DNSD_DNS_LISTEN="+held.LocalAddr().String(),
		"DNSD_TOKEN=test-token",
		"DNSD_STATE_FILE=",
		"DNSD_BLOCKLIST_DIR=",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("dnsd exited 0 on a DNS bind failure; want non-zero")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("dnsd kept running with its DNS port taken")
	}
}
