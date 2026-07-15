package resolve

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/pkg/api"
)

// Exchange sends req to upstream with optional local bind.
// Returns response, used address label, error.
func Exchange(ctx context.Context, req *dns.Msg, u api.Upstream, timeout time.Duration) (*dns.Msg, string, error) {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	proto := u.Proto
	if proto == "" {
		proto = api.UpstreamDNS
	}
	switch proto {
	case api.UpstreamDoH:
		return exchangeDoH(ctx, req, u)
	case api.UpstreamDoT:
		return exchangeDoT(ctx, req, u)
	default:
		return exchangeDNS(ctx, req, u)
	}
}

func exchangeDNS(ctx context.Context, req *dns.Msg, u api.Upstream) (*dns.Msg, string, error) {
	addr := u.Address
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	dialer := outboundDialer(u)
	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
		Dialer:  dialer,
	}
	resp, _, err := client.ExchangeContext(ctx, req, addr)
	if err == nil && resp != nil && resp.Truncated {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, addr)
	}
	if err != nil {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, addr)
	}
	return resp, "dns://" + addr, err
}

func exchangeDoT(ctx context.Context, req *dns.Msg, u api.Upstream) (*dns.Msg, string, error) {
	addr := u.Address
	if !strings.Contains(addr, ":") {
		addr += ":853"
	}
	serverName := u.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		serverName = host
	}
	dialer := outboundDialer(u)
	client := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
		Timeout: 4 * time.Second,
		Dialer:  dialer,
	}
	resp, _, err := client.ExchangeContext(ctx, req, addr)
	return resp, "tls://" + addr, err
}

func exchangeDoH(ctx context.Context, req *dns.Msg, u api.Upstream) (*dns.Msg, string, error) {
	url := u.Address
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	wire, err := req.Pack()
	if err != nil {
		return nil, url, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, url, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "dnsd/0.1")

	// Prefer IPv4: many hosts have broken/empty IPv6 routes → "cannot assign requested address".
	d := outboundDialer(u)
	d.FallbackDelay = -1 // disable Happy Eyeballs dual-stack racing weirdness
	baseDial := d.DialContext
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// try tcp4 first
			if c, err := baseDial(ctx, "tcp4", address); err == nil {
				return c, nil
			}
			return baseDial(ctx, network, address)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, url, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, url, fmt.Errorf("doh status %d: %s", resp.StatusCode, string(b))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, url, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, url, err
	}
	return msg, url, nil
}

func outboundDialer(u api.Upstream) *net.Dialer {
	d := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	if u.BindIP != "" {
		if ip := net.ParseIP(u.BindIP); ip != nil {
			// LocalAddr for TCP/UDP is set per-dial via Control + dual LocalAddr trick:
			// dns.Client reuses Dialer for both; set IP in Control and LocalAddr for UDP.
			d.LocalAddr = &net.TCPAddr{IP: ip} // may be ignored for UDP; Control handles bind IP
		}
	}
	if u.BindIP != "" || u.BindIface != "" {
		bindIP := net.ParseIP(u.BindIP)
		iface := u.BindIface
		d.Control = func(network, address string, c syscall.RawConn) error {
			return bindControl(network, bindIP, iface, c)
		}
	}
	return d
}
