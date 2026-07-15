package store

import (
	"testing"

	"github.com/reloadlife/dnsd/pkg/api"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in    string
		proto api.UpstreamProto
		addr  string
	}{
		{"1.1.1.1", api.UpstreamDNS, "1.1.1.1:53"},
		{"8.8.8.8:53", api.UpstreamDNS, "8.8.8.8:53"},
		{"dns://9.9.9.9", api.UpstreamDNS, "9.9.9.9:53"},
		{"tls://1.1.1.1", api.UpstreamDoT, "1.1.1.1:853"},
		{"dot://1.0.0.1:853", api.UpstreamDoT, "1.0.0.1:853"},
		{"https://dns.google/dns-query", api.UpstreamDoH, "https://dns.google/dns-query"},
		{"http://127.0.0.1:8080/dns-query", api.UpstreamDoH, "http://127.0.0.1:8080/dns-query"},
	}
	for _, c := range cases {
		u := ParseUpstream(c.in, api.Upstream{})
		if u.Proto != c.proto || u.Address != c.addr {
			t.Errorf("%q → proto=%s addr=%s want %s %s", c.in, u.Proto, u.Address, c.proto, c.addr)
		}
	}
	// preserve explicit proto
	u := ParseUpstream("1.1.1.1", api.Upstream{Proto: api.UpstreamDoT, ServerName: "x"})
	if u.Proto != api.UpstreamDoT || u.ServerName != "x" {
		t.Fatalf("%+v", u)
	}
}

func TestCreateProfileAndDefault(t *testing.T) {
	m := New()
	_, err := m.CreateProfile(api.ProfileCreateRequest{Name: ""})
	if err == nil {
		t.Fatal("expected name required")
	}
	_, err = m.CreateProfile(api.ProfileCreateRequest{Name: "a"})
	if err == nil {
		t.Fatal("expected upstream required")
	}
	def := true
	p, err := m.CreateProfile(api.ProfileCreateRequest{
		Name: "cf", UpstreamAddrs: []string{"1.1.1.1", "1.0.0.1"}, Default: &def,
		BindIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Default || len(p.Upstreams) != 2 || p.BindIP != "10.0.0.1" {
		t.Fatalf("%+v", p)
	}
	// second default clears first
	p2, err := m.CreateProfile(api.ProfileCreateRequest{
		Name: "g", UpstreamAddrs: []string{"8.8.8.8"}, Default: &def,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Default {
		t.Fatal("p2 should be default")
	}
	list := m.ListProfiles()
	var defs int
	for _, x := range list {
		if x.Default {
			defs++
		}
	}
	if defs != 1 {
		t.Fatalf("defaults=%d", defs)
	}
	dp := m.DefaultProfile()
	if dp == nil || dp.Name != "g" {
		t.Fatalf("%+v", dp)
	}
	if err := m.DeleteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteProfile("missing"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestCreateRuleCRUD(t *testing.T) {
	m := New()
	_, err := m.CreateRule(api.RuleCreateRequest{})
	if err == nil {
		t.Fatal("pattern required")
	}
	en := true
	r, err := m.CreateRule(api.RuleCreateRequest{
		Pattern: "evil.com", Match: api.MatchSuffix, Action: api.ActionBlock, Enabled: &en,
		Priority: 10, Answers: []string{"1.2.3.4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Name == "" || r.ID == "" {
		t.Fatalf("%+v", r)
	}
	m.IncRuleHit(r.ID)
	list := m.ListRules()
	if len(list) != 1 || list[0].HitCount != 1 {
		t.Fatalf("%+v", list)
	}
	// priority sort
	_, _ = m.CreateRule(api.RuleCreateRequest{
		Pattern: "a.com", Action: api.ActionAllow, Enabled: &en, Priority: 1,
	})
	list = m.ListRules()
	if list[0].Priority != 1 {
		t.Fatalf("sort %+v", list)
	}
	if err := m.DeleteRule(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteRule(r.ID); err == nil {
		t.Fatal("double delete")
	}
}

func TestReplaceAndConfig(t *testing.T) {
	m := New()
	m.ReplaceProfiles([]api.DnsProfile{{Name: "x", Upstreams: []api.Upstream{{Address: "1.1.1.1:53"}}}})
	if len(m.ListProfiles()) != 1 {
		t.Fatal()
	}
	m.ReplaceRules([]api.DnsRule{{Pattern: "y", Action: api.ActionBlock, Enabled: true}})
	if len(m.ListRules()) != 1 {
		t.Fatal()
	}
	m.SetDNSListen("0.0.0.0:53")
	if m.DNSListen() != "0.0.0.0:53" {
		t.Fatal(m.DNSListen())
	}
	m.SetTransparent(true)
	if !m.Transparent() {
		t.Fatal()
	}
	cfg := m.Config()
	cfg.BindIP = "192.168.1.1"
	cfg.QueryLogSize = 0 // should normalize
	m.SetConfig(cfg)
	got := m.Config()
	if got.BindIP != "192.168.1.1" || got.QueryLogSize != 2000 {
		t.Fatalf("%+v", got)
	}
	res := api.ApplyResult{OK: true, Message: "hi"}
	m.SetLastApply(res, 7)
	last, at, gen := m.LastApply()
	if !last.OK || gen != 7 || at.IsZero() {
		t.Fatalf("%+v %v %d", last, at, gen)
	}
}

func TestCreateProfileStructuredUpstreams(t *testing.T) {
	m := New()
	p, err := m.CreateProfile(api.ProfileCreateRequest{
		Name: "dot",
		Upstreams: []api.Upstream{
			{Address: "tls://1.1.1.1", ServerName: "cloudflare-dns.com", BindIface: "eth0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Upstreams[0].Proto != api.UpstreamDoT || p.Upstreams[0].BindIface != "eth0" {
		t.Fatalf("%+v", p.Upstreams[0])
	}
}
