// Package sni implements the TLS/HTTP relay that pairs with dnsd's DNS
// hijack: DNS points a configured domain at this node, and this relay carries
// the connection to the real origin over a chosen exit interface.
//
// It owns :443 on nodes that also run ocserv, so the rule that matters is:
// anything this relay does not positively route is handed to the fallback
// backend untouched. VPN ingress must survive every unknown case.
package sni

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/resolve"
	"github.com/reloadlife/dnsd/pkg/api"
)

const (
	peekTimeout    = 5 * time.Second
	defaultIdle    = 120 * time.Second
	defaultMaxConn = 4096
	dialTimeout    = 8 * time.Second
	resolveTTL     = 60 * time.Second
)

// Proxy runs the TLS and HTTP relay listeners.
type Proxy struct {
	// Config is read live on every connection so route edits apply without a
	// listener restart. Only listen addresses need Start().
	Config func() api.SniConfig

	mu     sync.Mutex
	tlsLn  net.Listener
	httpLn net.Listener
	cfg    api.SniConfig

	sem chan struct{}

	active, routed, fellBack, denied, errs int64
	bytesUp, bytesDown                     int64
	lastErr                                atomic.Value // string

	routeMu  sync.Mutex
	routeHit map[string]int64

	dnsMu    sync.Mutex
	dnsCache map[string]cachedIPs
}

type cachedIPs struct {
	ips []net.IP
	exp time.Time
}

// New builds a relay reading its config from cfg.
func New(cfg func() api.SniConfig) *Proxy {
	return &Proxy{Config: cfg, routeHit: map[string]int64{}, dnsCache: map[string]cachedIPs{}}
}

// Start binds the configured listeners, replacing any that are running.
// A disabled config just stops everything.
func (p *Proxy) Start(cfg api.SniConfig) error {
	p.Stop()
	if !cfg.Enabled {
		return nil
	}
	max := cfg.MaxConns
	if max <= 0 {
		max = defaultMaxConn
	}

	p.mu.Lock()
	p.cfg = cfg
	p.sem = make(chan struct{}, max)
	p.mu.Unlock()

	var errsOut []string
	if cfg.ListenTLS != "" {
		ln, err := net.Listen("tcp", cfg.ListenTLS)
		if err != nil {
			errsOut = append(errsOut, "sni tls "+cfg.ListenTLS+": "+err.Error())
		} else {
			p.mu.Lock()
			p.tlsLn = ln
			p.mu.Unlock()
			go p.serve(ln, true)
			log.Printf("dnsd: SNI relay listen %s", cfg.ListenTLS)
		}
	}
	if cfg.ListenHTTP != "" {
		ln, err := net.Listen("tcp", cfg.ListenHTTP)
		if err != nil {
			errsOut = append(errsOut, "sni http "+cfg.ListenHTTP+": "+err.Error())
		} else {
			p.mu.Lock()
			p.httpLn = ln
			p.mu.Unlock()
			go p.serve(ln, false)
			log.Printf("dnsd: HTTP relay listen %s", cfg.ListenHTTP)
		}
	}
	if len(errsOut) > 0 {
		return fmt.Errorf("%s", strings.Join(errsOut, "; "))
	}
	return nil
}

// Stop closes both listeners. In-flight connections drain on their own.
func (p *Proxy) Stop() {
	p.mu.Lock()
	tl, hl := p.tlsLn, p.httpLn
	p.tlsLn, p.httpLn = nil, nil
	p.mu.Unlock()
	if tl != nil {
		_ = tl.Close()
	}
	if hl != nil {
		_ = hl.Close()
	}
}

// Status reports live relay state.
func (p *Proxy) Status() api.SniStatus {
	p.mu.Lock()
	cfg := p.cfg
	tlsUp, httpUp := p.tlsLn != nil, p.httpLn != nil
	p.mu.Unlock()

	p.routeMu.Lock()
	byRoute := make(map[string]int64, len(p.routeHit))
	for k, v := range p.routeHit {
		byRoute[k] = v
	}
	p.routeMu.Unlock()

	last, _ := p.lastErr.Load().(string)
	live := p.Config()
	return api.SniStatus{
		Enabled:     live.Enabled,
		TLSServing:  tlsUp,
		HTTPServing: httpUp,
		ListenTLS:   cfg.ListenTLS,
		ListenHTTP:  cfg.ListenHTTP,
		Active:      atomic.LoadInt64(&p.active),
		Routed:      atomic.LoadInt64(&p.routed),
		FellBack:    atomic.LoadInt64(&p.fellBack),
		Denied:      atomic.LoadInt64(&p.denied),
		Errors:      atomic.LoadInt64(&p.errs),
		BytesUp:     atomic.LoadInt64(&p.bytesUp),
		BytesDown:   atomic.LoadInt64(&p.bytesDown),
		ByRoute:     byRoute,
		LastError:   last,
		Routes:      live.Routes,
	}
}

func (p *Proxy) serve(ln net.Listener, isTLS bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		p.mu.Lock()
		sem := p.sem
		p.mu.Unlock()
		select {
		case sem <- struct{}{}:
		default:
			// At the connection cap the safe move is to drop, not to queue —
			// a queued VPN client looks like a dead server.
			_ = c.Close()
			p.fail("max_conns reached")
			continue
		}
		go func() {
			defer func() { <-sem }()
			atomic.AddInt64(&p.active, 1)
			defer atomic.AddInt64(&p.active, -1)
			p.handle(c, isTLS)
		}()
	}
}

func (p *Proxy) handle(c net.Conn, isTLS bool) {
	defer func() { _ = c.Close() }()
	cfg := p.Config()

	var head bytes.Buffer
	var name string
	if isTLS {
		name = peekClientHello(c, &head, peekTimeout)
	} else {
		name = peekHTTPHost(c, &head, peekTimeout)
	}

	fallback := cfg.Fallback
	port := 443
	if !isTLS {
		fallback = cfg.FallbackHTTP
		port = 80
	}

	rt := resolve.MatchRoute(cfg.Routes, name)
	if rt == nil {
		p.toFallback(c, head.Bytes(), fallback, cfg)
		return
	}
	// The route matched but this client is not allowed to be relayed. It still
	// gets the fallback — on our nodes :443 is VPN ingress for the whole
	// internet, and rejecting here would take the fleet down.
	if !resolve.ClientAllowed(cfg.AllowCIDRs, remoteIP(c)) {
		atomic.AddInt64(&p.denied, 1)
		p.toFallback(c, head.Bytes(), fallback, cfg)
		return
	}

	if err := p.relay(c, head.Bytes(), name, port, *rt, cfg); err != nil {
		p.fail(name + ": " + err.Error())
	}
}

// relay dials the real origin and splices.
func (p *Proxy) relay(c net.Conn, head []byte, name string, port int, rt api.SniRoute, cfg api.SniConfig) error {
	ips, err := p.lookup(name, cfg)
	if err != nil {
		return err
	}
	bindIP := firstNonEmpty(rt.BindIP, cfg.BindIP)
	bindIface := firstNonEmpty(rt.BindIface, cfg.BindIface)
	d := resolve.OutboundDialer(bindIP, bindIface, dialTimeout)

	var lastErr error
	for _, ip := range ips {
		up, err := d.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			lastErr = err
			continue
		}
		p.hit(rt.Pattern)
		atomic.AddInt64(&p.routed, 1)
		if _, err := up.Write(head); err != nil {
			_ = up.Close()
			return err
		}
		p.splice(c, up, cfg)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", name)
	}
	return lastErr
}

// toFallback hands an unrouted connection to the local backend (ocserv),
// optionally announcing the real client with PROXY protocol v1.
func (p *Proxy) toFallback(c net.Conn, head []byte, addr string, cfg api.SniConfig) {
	if addr == "" {
		return
	}
	up, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		p.fail("fallback " + addr + ": " + err.Error())
		return
	}
	atomic.AddInt64(&p.fellBack, 1)
	// One write, not two. Sending the PROXY line and the replayed ClientHello
	// separately makes them separate segments, and ocserv then resets the
	// connection often enough to look like a flaky VPN rather than a bug here.
	var first []byte
	if cfg.FallbackProxyProto {
		first = append(first, proxyV1Header(c)...)
	}
	first = append(first, head...)
	if _, err := up.Write(first); err != nil {
		_ = up.Close()
		p.fail("fallback replay: " + err.Error())
		return
	}
	p.splice(c, up, cfg)
}

func (p *Proxy) splice(client, upstream net.Conn, cfg api.SniConfig) {
	idle := time.Duration(cfg.IdleTimeoutSec) * time.Second
	if idle <= 0 {
		idle = defaultIdle
	}
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, &idleReader{c: client, peer: upstream, idle: idle})
		atomic.AddInt64(&p.bytesUp, n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, &idleReader{c: upstream, peer: client, idle: idle})
		atomic.AddInt64(&p.bytesDown, n)
		done <- struct{}{}
	}()
	<-done
	_ = upstream.Close()
	_ = client.Close()
	<-done
}

// idleReader refreshes both deadlines on every read, so a connection dies only
// after genuine silence rather than at a fixed wall-clock cap. A long-lived
// idle-but-alive tunnel is normal traffic, not a leak.
type idleReader struct {
	c    net.Conn
	peer net.Conn
	idle time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	dl := time.Now().Add(r.idle)
	_ = r.c.SetReadDeadline(dl)
	_ = r.peer.SetWriteDeadline(dl)
	return r.c.Read(p)
}

// lookup resolves name via the configured resolvers, never via this dnsd, and
// drops any address that would send the relay back to itself.
func (p *Proxy) lookup(name string, cfg api.SniConfig) ([]net.IP, error) {
	p.dnsMu.Lock()
	if e, ok := p.dnsCache[name]; ok && time.Now().Before(e.exp) {
		p.dnsMu.Unlock()
		return e.ips, nil
	}
	p.dnsMu.Unlock()

	resolvers := cfg.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	// These queries leave the box, so they follow the same exit selector as the
	// traffic they are resolving for. Letting them take the default route would
	// expose the node's WAN address to the upstream resolver — the exact leak
	// the bind_iface plumbing exists to prevent.
	cl := &dns.Client{
		Timeout: 4 * time.Second,
		Dialer:  resolve.OutboundDialer(cfg.BindIP, cfg.BindIface, 4*time.Second),
	}

	var lastErr error
	for _, r := range resolvers {
		addr := strings.TrimSpace(r)
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		resp, _, err := cl.Exchange(m, addr)
		if err != nil {
			lastErr = err
			continue
		}
		var out []net.IP
		for _, rr := range resp.Answer {
			a, ok := rr.(*dns.A)
			if !ok {
				continue
			}
			if !relayable(a.A, cfg.Answers) {
				continue
			}
			out = append(out, a.A)
		}
		if len(out) == 0 {
			lastErr = fmt.Errorf("%s resolved to nothing relayable", name)
			continue
		}
		p.dnsMu.Lock()
		p.dnsCache[name] = cachedIPs{ips: out, exp: time.Now().Add(resolveTTL)}
		p.dnsMu.Unlock()
		return out, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolvers configured")
	}
	return nil, lastErr
}

// relayable rejects the addresses we hand out ourselves (the loop guard) plus
// anything that would turn the relay into an internal-network probe.
func relayable(ip net.IP, answers []string) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, a := range answers {
		if own := net.ParseIP(strings.TrimSpace(a)); own != nil && own.Equal(ip) {
			return false
		}
	}
	return true
}

// proxyV1Header renders a PROXY protocol v1 line for the backend.
func proxyV1Header(c net.Conn) string {
	src, sok := c.RemoteAddr().(*net.TCPAddr)
	dst, dok := c.LocalAddr().(*net.TCPAddr)
	if !sok || !dok {
		return "PROXY UNKNOWN\r\n"
	}
	proto := "TCP4"
	if src.IP.To4() == nil || dst.IP.To4() == nil {
		proto = "TCP6"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
}

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func (p *Proxy) hit(pattern string) {
	p.routeMu.Lock()
	p.routeHit[pattern]++
	p.routeMu.Unlock()
}

func (p *Proxy) fail(msg string) {
	atomic.AddInt64(&p.errs, 1)
	p.lastErr.Store(msg)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
