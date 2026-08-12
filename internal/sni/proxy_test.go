package sni

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/reloadlife/dnsd/pkg/api"
)

// backend stands in for ocserv: it records the first chunk it is handed.
func backend(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Deliberately ONE read. The PROXY line and the replayed ClientHello
		// must arrive together: ocserv resets the connection when they land as
		// separate segments, which shows up as an intermittently broken VPN.
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), got
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// clientHello dials addr and starts a TLS handshake so a real ClientHello with
// serverName goes out. The handshake never completes; we only need the bytes.
func clientHello(addr, serverName string) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
}

func startProxy(t *testing.T, cfg api.SniConfig) *Proxy {
	t.Helper()
	p := New(func() api.SniConfig { return cfg })
	if err := p.Start(cfg); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p
}

// An unrouted name must reach the fallback untouched, with the real client
// announced via PROXY protocol. This is the VPN-ingress path: if it breaks,
// every ocserv user on the node breaks.
func TestUnroutedGoesToFallbackWithProxyHeader(t *testing.T) {
	fb, got := backend(t)
	listen := freePort(t)
	startProxy(t, api.SniConfig{
		Enabled:            true,
		ListenTLS:          listen,
		Fallback:           fb,
		FallbackProxyProto: true,
		Answers:            []string{"203.0.113.1"},
		Routes:             []api.SniRoute{{Pattern: "docker.com", Match: api.MatchSuffix, Enabled: true}},
	})

	clientHello(listen, "vpn.example.com")

	select {
	case b := <-got:
		s := string(b)
		if !strings.HasPrefix(s, "PROXY TCP4 127.0.0.1 127.0.0.1 ") {
			t.Fatalf("missing PROXY v1 header, got %q", firstLine(s))
		}
		if !strings.Contains(s, "vpn.example.com") {
			t.Fatal("ClientHello was not replayed to the backend")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("fallback backend never received the connection")
	}
}

// A client outside AllowCIDRs must NOT be rejected — it falls back. Rejecting
// would drop VPN clients, since the relay shares :443 with ocserv.
func TestDeniedClientFallsBackInsteadOfClosing(t *testing.T) {
	fb, got := backend(t)
	listen := freePort(t)
	p := startProxy(t, api.SniConfig{
		Enabled:    true,
		ListenTLS:  listen,
		Fallback:   fb,
		AllowCIDRs: []string{"10.0.0.0/8"}, // 127.0.0.1 is not in it
		Answers:    []string{"203.0.113.1"},
		Routes:     []api.SniRoute{{Pattern: "docker.com", Match: api.MatchSuffix, Enabled: true}},
	})

	clientHello(listen, "registry.docker.com")

	select {
	case b := <-got:
		if !strings.Contains(string(b), "registry.docker.com") {
			t.Fatal("denied connection did not reach the fallback verbatim")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("denied client was dropped instead of falling back")
	}
	if p.Status().Denied == 0 {
		t.Fatal("denied counter not incremented")
	}
}

// relayable is the loop guard: our own advertised addresses and anything
// internal must never be dialed.
func TestRelayableRejectsOwnAnswersAndPrivate(t *testing.T) {
	answers := []string{"195.24.237.4"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"195.24.237.4", false}, // our own answer → loop
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"1.1.1.1", true},
	}
	for _, c := range cases {
		if got := relayable(net.ParseIP(c.ip), answers); got != c.want {
			t.Errorf("relayable(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestPeekHTTPHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("GET /v2/ HTTP/1.1\r\nHost: registry.docker.com\r\n\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var buf bytes.Buffer
	host := peekHTTPHost(c, &buf, 2*time.Second)
	if host != "registry.docker.com" {
		t.Fatalf("host = %q", host)
	}
	if !strings.Contains(buf.String(), "GET /v2/") {
		t.Fatal("request bytes were not captured for replay")
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
