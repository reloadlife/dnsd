package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/reloadlife/dnsd/pkg/api"
)

// Memory is an in-process store.
type Memory struct {
	mu        sync.RWMutex
	profiles  map[string]*api.DnsProfile
	rules     map[string]*api.DnsRule
	cfg       api.RuntimeConfig
	lastApply api.ApplyResult
	lastApplyAt time.Time
	lastGen   int64
}

// New returns a store with safe defaults (dev DNS on 5353).
func New() *Memory {
	m := &Memory{
		profiles: make(map[string]*api.DnsProfile),
		rules:    make(map[string]*api.DnsRule),
		cfg: api.RuntimeConfig{
			Listeners: api.ListenerConfig{
				UDP:     "127.0.0.1:5353",
				TCP:     "127.0.0.1:5353",
				DoHPath: "/dns-query",
			},
			DefaultUpstreams: []api.Upstream{
				{Address: "1.1.1.1:53", Proto: api.UpstreamDNS},
				{Address: "8.8.8.8:53", Proto: api.UpstreamDNS},
			},
			CacheTTLMax:  300,
			QueryLogSize: 2000,
		},
	}
	return m
}

// Config returns a copy of runtime config.
func (m *Memory) Config() api.RuntimeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// SetConfig replaces runtime config.
func (m *Memory) SetConfig(cfg api.RuntimeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.Listeners.DoHPath == "" {
		cfg.Listeners.DoHPath = "/dns-query"
	}
	if cfg.QueryLogSize <= 0 {
		cfg.QueryLogSize = 2000
	}
	if cfg.CacheTTLMax == 0 {
		cfg.CacheTTLMax = 300
	}
	// preserve defaults if empty
	if len(cfg.DefaultUpstreams) == 0 && len(m.cfg.DefaultUpstreams) > 0 {
		cfg.DefaultUpstreams = m.cfg.DefaultUpstreams
	}
	if cfg.Listeners.UDP == "" && cfg.Listeners.TCP == "" {
		cfg.Listeners.UDP = m.cfg.Listeners.UDP
		cfg.Listeners.TCP = m.cfg.Listeners.TCP
	}
	m.cfg = cfg
}

// DNSListen returns primary UDP listen (legacy helper).
func (m *Memory) DNSListen() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg.Listeners.UDP != "" {
		return m.cfg.Listeners.UDP
	}
	return m.cfg.Listeners.TCP
}

// SetDNSListen sets both UDP and TCP.
func (m *Memory) SetDNSListen(s string) {
	m.mu.Lock()
	m.cfg.Listeners.UDP = s
	m.cfg.Listeners.TCP = s
	m.mu.Unlock()
}

// Transparent returns transparent redirect flag.
func (m *Memory) Transparent() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Transparent
}

// SetTransparent sets the flag.
func (m *Memory) SetTransparent(v bool) {
	m.mu.Lock()
	m.cfg.Transparent = v
	m.mu.Unlock()
}

// ListProfiles returns sorted profiles.
func (m *Memory) ListProfiles() []api.DnsProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.DnsProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// CreateProfile creates a profile.
func (m *Memory) CreateProfile(req api.ProfileCreateRequest) (api.DnsProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return api.DnsProfile{}, fmt.Errorf("name required")
	}
	ups := normalizeUpstreams(req.Upstreams, req.UpstreamAddrs)
	if len(ups) == 0 {
		return api.DnsProfile{}, fmt.Errorf("at least one upstream required")
	}
	def := false
	if req.Default != nil {
		def = *req.Default
	}
	if def || len(m.profiles) == 0 {
		for _, p := range m.profiles {
			p.Default = false
		}
		def = true
	}
	bm := false
	if req.BlockMalware != nil {
		bm = *req.BlockMalware
	}
	now := time.Now().UTC()
	p := &api.DnsProfile{
		ID:            "dnsprof-" + shortID(),
		Name:          name,
		Upstreams:     ups,
		SearchDomains: clean(req.SearchDomains),
		Default:       def,
		BlockMalware:  bm,
		Description:   req.Description,
		BindIP:        req.BindIP,
		BindIface:     req.BindIface,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	m.profiles[p.ID] = p
	return *p, nil
}

// DeleteProfile removes a profile.
func (m *Memory) DeleteProfile(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.profiles, id)
	return nil
}

// ReplaceProfiles bulk-replaces profiles.
func (m *Memory) ReplaceProfiles(list []api.DnsProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profiles = make(map[string]*api.DnsProfile, len(list))
	for i := range list {
		p := list[i]
		if p.ID == "" {
			p.ID = "dnsprof-" + shortID()
		}
		cp := p
		m.profiles[cp.ID] = &cp
	}
}

// DefaultProfile returns the default profile or nil.
func (m *Memory) DefaultProfile() *api.DnsProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.profiles {
		if p.Default {
			cp := *p
			return &cp
		}
	}
	return nil
}

// ListRules returns priority-sorted rules.
func (m *Memory) ListRules() []api.DnsRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.DnsRule, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// CreateRule creates a rule.
func (m *Memory) CreateRule(req api.RuleCreateRequest) (api.DnsRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(req.Pattern) == "" {
		return api.DnsRule{}, fmt.Errorf("pattern required")
	}
	if req.Action == "" {
		return api.DnsRule{}, fmt.Errorf("action required")
	}
	en := true
	if req.Enabled != nil {
		en = *req.Enabled
	}
	match := req.Match
	if match == "" {
		match = api.MatchSuffix
	}
	pri := req.Priority
	if pri == 0 {
		pri = 100
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = string(req.Action) + ":" + req.Pattern
	}
	now := time.Now().UTC()
	r := &api.DnsRule{
		ID:          "dnsrule-" + shortID(),
		Priority:    pri,
		Name:        name,
		Enabled:     en,
		Match:       match,
		Pattern:     strings.TrimSpace(req.Pattern),
		QTypes:      clean(req.QTypes),
		Action:      req.Action,
		Answers:     clean(req.Answers),
		CNAME:       req.CNAME,
		TTL:         req.TTL,
		Upstreams:   req.Upstreams,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	m.rules[r.ID] = r
	return *r, nil
}

// DeleteRule removes a rule.
func (m *Memory) DeleteRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.rules, id)
	return nil
}

// ReplaceRules bulk-replaces rules.
func (m *Memory) ReplaceRules(list []api.DnsRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = make(map[string]*api.DnsRule, len(list))
	for i := range list {
		r := list[i]
		if r.ID == "" {
			r.ID = "dnsrule-" + shortID()
		}
		cp := r
		m.rules[cp.ID] = &cp
	}
}

// IncRuleHit increments hit_count for a rule.
func (m *Memory) IncRuleHit(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[id]; ok {
		r.HitCount++
	}
}

// SetLastApply records apply result.
func (m *Memory) SetLastApply(res api.ApplyResult, gen int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastApply = res
	m.lastApplyAt = time.Now().UTC()
	if gen != 0 {
		m.lastGen = gen
	}
}

// LastApply returns last apply metadata.
func (m *Memory) LastApply() (api.ApplyResult, time.Time, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastApply, m.lastApplyAt, m.lastGen
}

func normalizeUpstreams(ups []api.Upstream, addrs []string) []api.Upstream {
	out := make([]api.Upstream, 0, len(ups)+len(addrs))
	for _, u := range ups {
		if strings.TrimSpace(u.Address) == "" {
			continue
		}
		out = append(out, ParseUpstream(u.Address, u))
	}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		out = append(out, ParseUpstream(a, api.Upstream{}))
	}
	return out
}

// ParseUpstream normalizes address string into Upstream.
func ParseUpstream(addr string, base api.Upstream) api.Upstream {
	u := base
	u.Address = strings.TrimSpace(addr)
	if u.Proto != "" {
		return u
	}
	low := strings.ToLower(u.Address)
	switch {
	case strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://"):
		u.Proto = api.UpstreamDoH
	case strings.HasPrefix(low, "tls://") || strings.HasPrefix(low, "dot://"):
		u.Proto = api.UpstreamDoT
		u.Address = strings.TrimPrefix(strings.TrimPrefix(u.Address, "tls://"), "dot://")
		u.Address = strings.TrimPrefix(u.Address, "TLS://")
		if !strings.Contains(u.Address, ":") {
			u.Address += ":853"
		}
	case strings.HasPrefix(low, "dns://") || strings.HasPrefix(low, "udp://"):
		u.Proto = api.UpstreamDNS
		u.Address = strings.TrimPrefix(strings.TrimPrefix(u.Address, "dns://"), "udp://")
		if !strings.Contains(u.Address, ":") {
			u.Address += ":53"
		}
	default:
		u.Proto = api.UpstreamDNS
		if !strings.Contains(u.Address, ":") {
			u.Address += ":53"
		}
	}
	return u
}

func clean(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func shortID() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
}
