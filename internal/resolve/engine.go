// Package resolve implements the DNS data plane: match → block/rewrite/forward → upstream.
package resolve

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/store"
	"github.com/reloadlife/dnsd/pkg/api"
)

// Engine answers DNS queries with policy + upstreams.
type Engine struct {
	Store *store.Memory
	Tel   *Telemetry
	Cache *Cache

	mu sync.RWMutex
}

// NewEngine builds an engine bound to store + telemetry.
func NewEngine(st *store.Memory, tel *Telemetry) *Engine {
	return &Engine{
		Store: st,
		Tel:   tel,
		Cache: NewCache(4096),
	}
}

// ServeDNS implements dns.Handler.
func (e *Engine) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	proto := protoFromWriter(w)
	client := ""
	if a := w.RemoteAddr(); a != nil {
		host, _, err := net.SplitHostPort(a.String())
		if err == nil {
			client = host
		} else {
			client = a.String()
		}
	}
	resp, ev := e.Handle(context.Background(), r, client, proto)
	if resp == nil {
		// drop
		e.Tel.Record(ev)
		return
	}
	_ = w.WriteMsg(resp)
	e.Tel.Record(ev)
}

// Handle processes one message (also used by /v1/resolve and DoH).
func (e *Engine) Handle(ctx context.Context, req *dns.Msg, client, proto string) (*dns.Msg, api.QueryEvent) {
	start := time.Now()
	ev := api.QueryEvent{
		ID:       uuid.NewString()[:12],
		Time:     start.UTC().Format(time.RFC3339Nano),
		Client:   client,
		Protocol: proto,
		Action:   "allow",
	}
	if req == nil || len(req.Question) == 0 {
		ev.Action = "error"
		ev.Error = "empty question"
		ev.RCode = dns.RcodeToString[dns.RcodeFormatError]
		m := new(dns.Msg)
		if req != nil {
			m.SetRcode(req, dns.RcodeFormatError)
		}
		return m, ev
	}
	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	ev.Name = name
	ev.QType = dns.TypeToString[q.Qtype]

	// Production guards: length, class, qtype
	if err := validateQuestion(name, q); err != nil {
		ev.Action = "error"
		ev.Error = err.Error()
		ev.RCode = dns.RcodeToString[dns.RcodeFormatError]
		ev.LatencyMs = msSince(start)
		return rcode(req, dns.RcodeFormatError), ev
	}

	// Match rule
	rule := e.match(name, q.Qtype)
	if rule != nil {
		ev.RuleID = rule.ID
		ev.RuleName = rule.Name
		e.Store.IncRuleHit(rule.ID)
		switch rule.Action {
		case api.ActionBlock:
			ev.Action = "block"
			ev.RCode = "NXDOMAIN"
			ev.LatencyMs = msSince(start)
			return nxdomain(req), ev
		case api.ActionRefuse:
			ev.Action = "refuse"
			ev.RCode = "REFUSED"
			ev.LatencyMs = msSince(start)
			return rcode(req, dns.RcodeRefused), ev
		case api.ActionDrop:
			ev.Action = "drop"
			ev.RCode = "DROP"
			ev.LatencyMs = msSince(start)
			return nil, ev
		case api.ActionSinkhole, api.ActionRewrite:
			ev.Action = string(rule.Action)
			msg, answers, err := synthesize(req, rule)
			if err != nil {
				ev.Action = "error"
				ev.Error = err.Error()
				ev.RCode = "SERVFAIL"
				ev.LatencyMs = msSince(start)
				return rcode(req, dns.RcodeServerFailure), ev
			}
			ev.Answers = answers
			ev.RCode = dns.RcodeToString[msg.Rcode]
			ev.LatencyMs = msSince(start)
			return msg, ev
		case api.ActionForward:
			ev.Action = "forward"
			ups := rule.Upstreams
			if len(ups) == 0 {
				ups = e.defaultUpstreams()
			}
			return e.forward(ctx, req, ups, &ev, start)
		case api.ActionAllow:
			// fall through to default upstream
		}
	}

	// Cache
	if msg, ok := e.Cache.Get(name, q.Qtype); ok {
		out := msg.Copy()
		out.Id = req.Id
		ev.Action = "cache"
		ev.RCode = dns.RcodeToString[out.Rcode]
		ev.Answers = extractAnswers(out)
		ev.LatencyMs = msSince(start)
		e.Tel.CacheHit()
		return out, ev
	}
	e.Tel.CacheMiss()

	ups := e.defaultUpstreams()
	return e.forward(ctx, req, ups, &ev, start)
}

func (e *Engine) forward(ctx context.Context, req *dns.Msg, ups []api.Upstream, ev *api.QueryEvent, start time.Time) (*dns.Msg, api.QueryEvent) {
	if len(ups) == 0 {
		ev.Action = "error"
		ev.Error = "no upstreams configured"
		ev.RCode = "SERVFAIL"
		ev.LatencyMs = msSince(start)
		return rcode(req, dns.RcodeServerFailure), *ev
	}
	cfg := e.Store.Config()
	var lastErr error
	for _, u := range ups {
		if u.Enabled != nil && !*u.Enabled {
			continue
		}
		// inherit global bind
		if u.BindIP == "" {
			u.BindIP = cfg.BindIP
		}
		if u.BindIface == "" {
			u.BindIface = cfg.BindIface
		}
		// profile defaults already merged into defaultUpstreams
		resp, used, err := Exchange(ctx, req, u, 4*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		ev.Upstream = used
		if ev.Action == "" || ev.Action == "allow" {
			ev.Action = "allow"
		}
		ev.RCode = dns.RcodeToString[resp.Rcode]
		ev.Answers = extractAnswers(resp)
		ev.LatencyMs = msSince(start)
		// cache positive / nxdomain briefly
		if len(req.Question) > 0 {
			ttl := minTTL(resp, cfg.CacheTTLMax)
			e.Cache.Put(strings.TrimSuffix(strings.ToLower(req.Question[0].Name), "."), req.Question[0].Qtype, resp, ttl)
		}
		return resp, *ev
	}
	ev.Action = "error"
	if lastErr != nil {
		ev.Error = lastErr.Error()
	} else {
		ev.Error = "all upstreams failed"
	}
	ev.RCode = "SERVFAIL"
	ev.LatencyMs = msSince(start)
	return rcode(req, dns.RcodeServerFailure), *ev
}

func (e *Engine) defaultUpstreams() []api.Upstream {
	cfg := e.Store.Config()
	if p := e.Store.DefaultProfile(); p != nil && len(p.Upstreams) > 0 {
		out := make([]api.Upstream, len(p.Upstreams))
		copy(out, p.Upstreams)
		for i := range out {
			if out[i].BindIP == "" {
				out[i].BindIP = firstNonEmpty(p.BindIP, cfg.BindIP)
			}
			if out[i].BindIface == "" {
				out[i].BindIface = firstNonEmpty(p.BindIface, cfg.BindIface)
			}
			out[i] = store.ParseUpstream(out[i].Address, out[i])
		}
		return out
	}
	out := make([]api.Upstream, len(cfg.DefaultUpstreams))
	for i, u := range cfg.DefaultUpstreams {
		if u.BindIP == "" {
			u.BindIP = cfg.BindIP
		}
		if u.BindIface == "" {
			u.BindIface = cfg.BindIface
		}
		out[i] = store.ParseUpstream(u.Address, u)
	}
	return out
}

func (e *Engine) match(name string, qtype uint16) *api.DnsRule {
	rules := e.Store.ListRules()
	for i := range rules {
		r := rules[i]
		if !r.Enabled {
			continue
		}
		if len(r.QTypes) > 0 && !qtypeAllowed(r.QTypes, qtype) {
			continue
		}
		if matchName(r.Match, r.Pattern, name) {
			cp := r
			return &cp
		}
	}
	return nil
}

func matchName(kind api.MatchKind, pattern, name string) bool {
	pat := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	pat = strings.TrimPrefix(pat, "*.")
	switch kind {
	case api.MatchExact:
		return name == pat
	case api.MatchGlob:
		ok, _ := filepath.Match(pat, name)
		if ok {
			return true
		}
		// also try with leading *.
		if !strings.HasPrefix(pat, "*") {
			ok, _ = filepath.Match("*."+pat, name)
		}
		return ok
	case api.MatchSuffix, "":
		return name == pat || strings.HasSuffix(name, "."+pat)
	default:
		return name == pat || strings.HasSuffix(name, "."+pat)
	}
}

func qtypeAllowed(list []string, qtype uint16) bool {
	want := dns.TypeToString[qtype]
	for _, t := range list {
		if strings.EqualFold(t, want) || t == "*" {
			return true
		}
	}
	return false
}

func synthesize(req *dns.Msg, rule *api.DnsRule) (*dns.Msg, []string, error) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	ttl := rule.TTL
	if ttl == 0 {
		ttl = 60
	}
	q := req.Question[0]
	var answers []string

	if rule.CNAME != "" {
		cname := dns.Fqdn(rule.CNAME)
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: cname,
		})
		answers = append(answers, "CNAME "+cname)
		// if client asked for CNAME we're done; for A/AAAA leave just CNAME (resolver follows)
		return m, answers, nil
	}

	for _, a := range rule.Answers {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		ip := net.ParseIP(a)
		if ip == nil {
			// treat as CNAME target
			cname := dns.Fqdn(a)
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: cname,
			})
			answers = append(answers, "CNAME "+cname)
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip4,
				})
				answers = append(answers, ip4.String())
			}
		} else {
			if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
				answers = append(answers, ip.String())
			}
		}
	}
	if len(m.Answer) == 0 {
		// no matching type → NODATA
		m.Rcode = dns.RcodeSuccess
	}
	return m, answers, nil
}

func nxdomain(req *dns.Msg) *dns.Msg {
	return rcode(req, dns.RcodeNameError)
}

func rcode(req *dns.Msg, code int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, code)
	return m
}

func extractAnswers(m *dns.Msg) []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, rr := range m.Answer {
		out = append(out, rr.String())
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func minTTL(m *dns.Msg, cap uint32) time.Duration {
	if cap == 0 {
		cap = 300
	}
	var min uint32 = cap
	found := false
	for _, rr := range m.Answer {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
		found = true
	}
	if !found {
		min = 30
	}
	if min > cap {
		min = cap
	}
	if min < 5 {
		min = 5
	}
	return time.Duration(min) * time.Second
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

func validateQuestion(name string, q dns.Question) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if len(name) > 253 {
		return fmt.Errorf("name too long")
	}
	if q.Qclass != dns.ClassINET {
		return fmt.Errorf("unsupported class %d", q.Qclass)
	}
	// reject path-like / control characters
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid name character")
		}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func protoFromWriter(w dns.ResponseWriter) string {
	// DoH sets via custom wrapper; default inspect network
	if p, ok := w.(interface{ Proto() string }); ok {
		return p.Proto()
	}
	a := w.LocalAddr()
	if a == nil {
		return "udp"
	}
	if strings.Contains(strings.ToLower(a.Network()), "tcp") {
		return "tcp"
	}
	return "udp"
}

// PlanApply returns host commands for transparent DNS redirect.
func PlanApply(cfg api.RuntimeConfig) []string {
	var cmds []string
	listen := cfg.Listeners.UDP
	if listen == "" {
		listen = ":53"
	}
	// extract port
	port := "53"
	if _, p, err := net.SplitHostPort(listen); err == nil && p != "" {
		port = p
	}
	if cfg.Transparent {
		cmds = append(cmds,
			"nft add table inet dnsd 2>/dev/null || true",
			"nft 'add chain inet dnsd prerouting { type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true",
			fmt.Sprintf("nft add rule inet dnsd prerouting udp dport 53 redirect to :%s", port),
			fmt.Sprintf("nft add rule inet dnsd prerouting tcp dport 53 redirect to :%s", port),
		)
	}
	if cfg.Listeners.UDP != "" {
		cmds = append(cmds, "listen udp "+cfg.Listeners.UDP)
	}
	if cfg.Listeners.TCP != "" {
		cmds = append(cmds, "listen tcp "+cfg.Listeners.TCP)
	}
	if cfg.Listeners.DoT != "" {
		cmds = append(cmds, "listen dot "+cfg.Listeners.DoT)
	}
	if cfg.Listeners.DoH != "" {
		cmds = append(cmds, "listen doh "+cfg.Listeners.DoH+cfg.Listeners.DoHPath)
	}
	return cmds
}
