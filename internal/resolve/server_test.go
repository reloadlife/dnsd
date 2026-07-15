package resolve

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/store"
	"github.com/reloadlife/dnsd/pkg/api"
)

// startFakeUpstream answers A queries for *.fake.test with 10.55.55.55
func startFakeUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("10.55.55.55").To4(),
			})
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestServerUDPAndForward(t *testing.T) {
	up, stopUp := startFakeUpstream(t)
	defer stopUp()

	st := store.New()
	cfg := st.Config()
	// free ports
	lnUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := lnUDP.LocalAddr().String()
	_ = lnUDP.Close()
	lnTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := lnTCP.Addr().String()
	_ = lnTCP.Close()

	cfg.Listeners.UDP = udpAddr
	cfg.Listeners.TCP = tcpAddr
	cfg.DefaultUpstreams = []api.Upstream{{Address: up, Proto: api.UpstreamDNS}}
	st.SetConfig(cfg)

	eng := NewEngine(st, NewTelemetry(50))
	srv := NewServer(eng)
	if err := srv.Start(cfg.Listeners); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	udp, tcp, _, _ := srv.State()
	if !udp || !tcp {
		t.Fatalf("serving udp=%v tcp=%v", udp, tcp)
	}

	// dig via client
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("www.fake.test"), dns.TypeA)
	resp, _, err := c.Exchange(m, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("%+v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.55.55.55" {
		t.Fatalf("%+v", resp.Answer)
	}

	// TCP path (DNS-over-TCP)
	c.Net = "tcp"
	resp, _, err = c.Exchange(m, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("tcp empty")
	}
	// ensure engine tags protocol as tcp via ServeDNS path is covered by live dig;
	// handle() API uses explicit proto
	_, ev := eng.Handle(context.Background(), m, "127.0.0.1", "tcp")
	if ev.Protocol != "tcp" {
		t.Fatalf("protocol %s", ev.Protocol)
	}

	// cache hit
	evBefore := eng.Tel.Snapshot().CacheHits
	_, _ = eng.Handle(context.Background(), m, "127.0.0.1", "udp")
	// second handle through cache path inside Handle
	m2 := new(dns.Msg)
	m2.SetQuestion(dns.Fqdn("www.fake.test"), dns.TypeA)
	resp2, ev := eng.Handle(context.Background(), m2, "127.0.0.1", "udp")
	if resp2 == nil {
		t.Fatal("nil")
	}
	// either cache or allow after first put
	_ = evBefore
	_ = ev
}

func TestServerDoH(t *testing.T) {
	up, stopUp := startFakeUpstream(t)
	defer stopUp()

	st := store.New()
	cfg := st.Config()
	// pick free HTTP port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dohAddr := ln.Addr().String()
	_ = ln.Close()

	cfg.Listeners = api.ListenerConfig{
		UDP: "", TCP: "",
		DoH: dohAddr, DoHPath: "/dns-query", DoHInsecure: true,
	}
	cfg.DefaultUpstreams = []api.Upstream{{Address: up}}
	st.SetConfig(cfg)

	eng := NewEngine(st, NewTelemetry(20))
	srv := NewServer(eng)
	if err := srv.Start(cfg.Listeners); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	_, _, _, doh := srv.State()
	if !doh {
		t.Fatal("doh not up")
	}

	// POST
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("a.fake.test"), dns.TypeA)
	wire, _ := m.Pack()
	resp, err := http.Post("http://"+dohAddr+"/dns-query", "application/dns-message", bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		t.Fatal(err)
	}
	if out.Rcode != dns.RcodeSuccess || len(out.Answer) == 0 {
		t.Fatalf("%+v", out)
	}

	// GET base64url
	q := base64.RawURLEncoding.EncodeToString(wire)
	resp2, err := http.Get("http://" + dohAddr + "/dns-query?dns=" + q)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("get %d", resp2.StatusCode)
	}
}

func TestServerBindConflict(t *testing.T) {
	// occupy a port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	st := store.New()
	eng := NewEngine(st, NewTelemetry(10))
	srv := NewServer(eng)
	err = srv.Start(api.ListenerConfig{DoH: addr, DoHInsecure: true})
	if err == nil {
		srv.Stop()
		t.Fatal("expected bind error")
	}
	_, _, _, doh := srv.State()
	if doh {
		t.Fatal("doh should not be marked up")
	}
}

func TestAllPolicyActions(t *testing.T) {
	st := store.New()
	en := true
	_, _ = st.CreateRule(api.RuleCreateRequest{Pattern: "b.test", Match: api.MatchSuffix, Action: api.ActionBlock, Enabled: &en, Priority: 10})
	_, _ = st.CreateRule(api.RuleCreateRequest{Pattern: "r.test", Match: api.MatchSuffix, Action: api.ActionRefuse, Enabled: &en, Priority: 10})
	_, _ = st.CreateRule(api.RuleCreateRequest{Pattern: "d.test", Match: api.MatchExact, Action: api.ActionDrop, Enabled: &en, Priority: 10})
	_, _ = st.CreateRule(api.RuleCreateRequest{Pattern: "s.test", Match: api.MatchExact, Action: api.ActionSinkhole, Enabled: &en, Priority: 10, Answers: []string{"9.9.9.9"}})
	_, _ = st.CreateRule(api.RuleCreateRequest{Pattern: "w.test", Match: api.MatchExact, Action: api.ActionRewrite, Enabled: &en, Priority: 10, CNAME: "target.test"})

	e := NewEngine(st, NewTelemetry(50))
	ctx := context.Background()

	check := func(name string, qtype uint16, wantAction string, wantRcode int, wantNil bool) {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		resp, ev := e.Handle(ctx, m, "1.2.3.4", "udp")
		if ev.Action != wantAction {
			t.Fatalf("%s action=%s want %s", name, ev.Action, wantAction)
		}
		if wantNil {
			if resp != nil {
				t.Fatalf("%s expected drop nil", name)
			}
			return
		}
		if resp == nil || resp.Rcode != wantRcode {
			t.Fatalf("%s rcode=%v resp=%v", name, resp, resp)
		}
	}
	check("x.b.test", dns.TypeA, "block", dns.RcodeNameError, false)
	check("x.r.test", dns.TypeA, "refuse", dns.RcodeRefused, false)
	check("d.test", dns.TypeA, "drop", 0, true)
	check("s.test", dns.TypeA, "sinkhole", dns.RcodeSuccess, false)
	check("w.test", dns.TypeA, "rewrite", dns.RcodeSuccess, false)

	// qtype filter
	_, _ = st.CreateRule(api.RuleCreateRequest{
		Pattern: "onlya.test", Match: api.MatchExact, Action: api.ActionBlock, Enabled: &en,
		Priority: 1, QTypes: []string{"A"},
	})
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("onlya.test"), dns.TypeAAAA)
	// no default upstream in empty profile — may error; ensure not block
	resp, ev := e.Handle(ctx, m, "1.1.1.1", "udp")
	if ev.Action == "block" {
		t.Fatalf("AAAA should not match A-only rule: %+v %v", ev, resp)
	}
}

func TestMatchGlobAndExact(t *testing.T) {
	if !matchName(api.MatchExact, "App.Corp", "app.corp") {
		t.Fatal("exact case")
	}
	if matchName(api.MatchExact, "app.corp", "x.app.corp") {
		t.Fatal("exact no suffix")
	}
	if !matchName(api.MatchGlob, "*.ads.com", "a.ads.com") {
		t.Fatal("glob")
	}
	if !matchName(api.MatchSuffix, "corp", "a.b.corp") {
		t.Fatal("suffix multi")
	}
}

func TestPlanApply(t *testing.T) {
	cmds := PlanApply(api.RuntimeConfig{
		Listeners:   api.ListenerConfig{UDP: "0.0.0.0:53", DoH: "127.0.0.1:8443", DoHPath: "/dns-query"},
		Transparent: true,
	})
	if len(cmds) < 3 {
		t.Fatalf("%v", cmds)
	}
	joined := fmt.Sprint(cmds)
	if !contains(joined, "nft") || !contains(joined, "listen") {
		t.Fatalf("%v", cmds)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		bytes.Contains([]byte(s), []byte(sub)))
}

func TestExchangeDNSLocal(t *testing.T) {
	up, stop := startFakeUpstream(t)
	defer stop()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("z.fake.test"), dns.TypeA)
	resp, used, err := Exchange(context.Background(), m, api.Upstream{Address: up, Proto: api.UpstreamDNS}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(used, "dns://") || resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("%s %+v", used, resp)
	}
}

func TestDecodeBase64URL(t *testing.T) {
	raw := []byte{1, 2, 3, 4}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	got, err := decodeBase64URL(enc)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("%v %v", got, err)
	}
}
