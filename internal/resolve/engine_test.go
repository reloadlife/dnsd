package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/store"
	"github.com/reloadlife/dnsd/pkg/api"
)

func TestMatchSuffix(t *testing.T) {
	st := store.New()
	en := true
	_, _ = st.CreateRule(api.RuleCreateRequest{
		Enabled: &en, Match: api.MatchSuffix, Pattern: "evil.example",
		Action: api.ActionBlock, Priority: 10,
	})
	_, _ = st.CreateRule(api.RuleCreateRequest{
		Enabled: &en, Match: api.MatchExact, Pattern: "app.corp",
		Action: api.ActionRewrite, Priority: 20, Answers: []string{"10.0.0.1"},
	})
	tel := NewTelemetry(100)
	e := NewEngine(st, tel)

	if r := e.match("a.evil.example", dns.TypeA); r == nil || r.Action != api.ActionBlock {
		t.Fatalf("expected block, got %#v", r)
	}
	if r := e.match("app.corp", dns.TypeA); r == nil || r.Action != api.ActionRewrite {
		t.Fatalf("expected rewrite, got %#v", r)
	}
	if r := e.match("ok.example", dns.TypeA); r != nil {
		t.Fatalf("expected no match, got %#v", r)
	}
}

func TestHandleBlockAndRewrite(t *testing.T) {
	st := store.New()
	en := true
	_, _ = st.CreateRule(api.RuleCreateRequest{
		Enabled: &en, Match: api.MatchSuffix, Pattern: "blocked.test",
		Action: api.ActionBlock, Priority: 10,
	})
	_, _ = st.CreateRule(api.RuleCreateRequest{
		Enabled: &en, Match: api.MatchExact, Pattern: "app.local",
		Action: api.ActionRewrite, Priority: 5, Answers: []string{"192.168.1.50"},
	})
	e := NewEngine(st, NewTelemetry(100))

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("x.blocked.test"), dns.TypeA)
	resp, ev := e.Handle(context.Background(), m, "127.0.0.1", "udp")
	if resp == nil || resp.Rcode != dns.RcodeNameError || ev.Action != "block" {
		t.Fatalf("block: rcode=%v action=%s", resp, ev.Action)
	}

	m2 := new(dns.Msg)
	m2.SetQuestion(dns.Fqdn("app.local"), dns.TypeA)
	resp2, ev2 := e.Handle(context.Background(), m2, "127.0.0.1", "udp")
	if resp2 == nil || len(resp2.Answer) == 0 || ev2.Action != "rewrite" {
		t.Fatalf("rewrite: %+v answers=%v", ev2, resp2)
	}
	a, ok := resp2.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.168.1.50" {
		t.Fatalf("answer %+v", resp2.Answer)
	}
}

func TestParseUpstream(t *testing.T) {
	u := store.ParseUpstream("1.1.1.1", api.Upstream{})
	if u.Proto != api.UpstreamDNS || u.Address != "1.1.1.1:53" {
		t.Fatalf("%+v", u)
	}
	u = store.ParseUpstream("tls://1.1.1.1", api.Upstream{})
	if u.Proto != api.UpstreamDoT {
		t.Fatalf("%+v", u)
	}
	u = store.ParseUpstream("https://cloudflare-dns.com/dns-query", api.Upstream{})
	if u.Proto != api.UpstreamDoH {
		t.Fatalf("%+v", u)
	}
}

func TestCache(t *testing.T) {
	c := NewCache(10)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
	c.Put("example.com", dns.TypeA, m, 0) // zero ttl ignored
	if _, ok := c.Get("example.com", dns.TypeA); ok {
		t.Fatal("should miss")
	}
	c.Put("example.com", dns.TypeA, m, time.Minute)
	got, ok := c.Get("example.com", dns.TypeA)
	if !ok || got == nil {
		t.Fatal("expected hit")
	}
}

func TestTelemetry(t *testing.T) {
	tel := NewTelemetry(10)
	for i := 0; i < 5; i++ {
		tel.Record(api.QueryEvent{Name: "a.com", Action: "allow", RCode: "NOERROR", QType: "A", Protocol: "udp", Client: "1.1.1.1"})
	}
	tel.Record(api.QueryEvent{Name: "bad.com", Action: "block", RCode: "NXDOMAIN", QType: "A", Protocol: "udp", Client: "1.1.1.1"})
	snap := tel.Snapshot()
	if snap.QueryCount != 6 || snap.BlockCount != 1 {
		t.Fatalf("%+v", snap)
	}
	if len(snap.TopDomains) == 0 {
		t.Fatal("expected top domains")
	}
}
