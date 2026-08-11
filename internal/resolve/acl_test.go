package resolve

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/store"
	"github.com/reloadlife/dnsd/pkg/api"
)

func TestClientAllowed(t *testing.T) {
	cidrs := []string{"195.24.237.0/24", "10.0.0.0/8"}
	cases := []struct {
		client string
		want   bool
	}{
		{"195.24.237.62", true},
		{"10.20.0.5", true},
		{"8.8.8.8", false},
		{"195.24.238.1", false},
		{"api", true}, // control-plane callers are not network clients
	}
	for _, c := range cases {
		if got := ClientAllowed(cidrs, c.client); got != c.want {
			t.Errorf("ClientAllowed(%s) = %v, want %v", c.client, got, c.want)
		}
	}
	if !ClientAllowed(nil, "8.8.8.8") {
		t.Error("empty ACL must stay open — a stock resolver cannot start refusing on upgrade")
	}
}

func hijackEngine(t *testing.T) *Engine {
	t.Helper()
	st := store.New()
	cfg := st.Config()
	cfg.AllowCIDRs = []string{"195.24.237.0/24"}
	cfg.Sni = &api.SniConfig{
		Enabled: true,
		Answers: []string{"195.24.237.4", "49.12.132.21"},
		Routes: []api.SniRoute{
			{Pattern: "docker.com", Match: api.MatchSuffix, Enabled: true},
			{Pattern: "off.example", Match: api.MatchSuffix, Enabled: false},
		},
	}
	st.SetConfig(cfg)
	return NewEngine(st, NewTelemetry(100))
}

func ask(t *testing.T, e *Engine, name string, qtype uint16, client string) (*dns.Msg, api.QueryEvent) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return e.Handle(context.Background(), m, client, "udp")
}

func TestSniHijackAnswersNodeAddresses(t *testing.T) {
	e := hijackEngine(t)

	msg, ev := ask(t, e, "registry.docker.com", dns.TypeA, "195.24.237.62")
	if ev.Action != "rewrite" {
		t.Fatalf("action = %s, want rewrite", ev.Action)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("got %d answers, want both node addresses", len(msg.Answer))
	}

	// AAAA must be NODATA. A real AAAA would let a dual-stack client reach the
	// origin directly and silently bypass the relay.
	msg6, _ := ask(t, e, "registry.docker.com", dns.TypeAAAA, "195.24.237.62")
	if len(msg6.Answer) != 0 {
		t.Fatalf("AAAA returned %d answers, want NODATA", len(msg6.Answer))
	}
	if msg6.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA rcode = %s, want NOERROR", dns.RcodeToString[msg6.Rcode])
	}
}

func TestDisallowedClientRefused(t *testing.T) {
	e := hijackEngine(t)
	msg, ev := ask(t, e, "registry.docker.com", dns.TypeA, "8.8.8.8")
	if msg.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[msg.Rcode])
	}
	if ev.RuleName != "acl" {
		t.Fatalf("rule = %q, want acl", ev.RuleName)
	}
}

func TestDisabledRouteIsNotHijacked(t *testing.T) {
	e := hijackEngine(t)
	_, ev := ask(t, e, "thing.off.example", dns.TypeA, "195.24.237.62")
	if ev.Action == "rewrite" {
		t.Fatal("disabled route was hijacked")
	}
}
