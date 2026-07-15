package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/reloadlife/dnsd/pkg/api"
)

// Snapshot is the on-disk durable state.
type Snapshot struct {
	Version    int               `json:"version"`
	SavedAt    string            `json:"saved_at"`
	Generation int64             `json:"generation"`
	Config     api.RuntimeConfig `json:"config"`
	Profiles   []api.DnsProfile  `json:"profiles"`
	Rules      []api.DnsRule     `json:"rules"`
}

const snapshotVersion = 1

// Export returns a durable snapshot of current state.
func (m *Memory) Export() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		Version:    snapshotVersion,
		SavedAt:    time.Now().UTC().Format(time.RFC3339),
		Generation: m.lastGen,
		Config:     m.cfg,
		Profiles:   cloneProfiles(m.profiles),
		Rules:      cloneRules(m.rules),
	}
}

// Import replaces in-memory state from a snapshot (config/profiles/rules).
func (m *Memory) Import(s Snapshot) error {
	if s.Version != 0 && s.Version != snapshotVersion {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Config.Listeners.DoHPath == "" && s.Config.Listeners.UDP == "" && len(s.Profiles) == 0 && len(s.Rules) == 0 {
		// empty snapshot — keep defaults
		return nil
	}
	if s.Config.Listeners.UDP != "" || s.Config.Listeners.TCP != "" || len(s.Config.DefaultUpstreams) > 0 ||
		s.Config.BindIP != "" || s.Config.BindIface != "" {
		cfg := s.Config
		if cfg.Listeners.DoHPath == "" {
			cfg.Listeners.DoHPath = "/dns-query"
		}
		if cfg.QueryLogSize <= 0 {
			cfg.QueryLogSize = 2000
		}
		if cfg.CacheTTLMax == 0 {
			cfg.CacheTTLMax = 300
		}
		m.cfg = cfg
	}
	m.profiles = make(map[string]*api.DnsProfile, len(s.Profiles))
	for i := range s.Profiles {
		p := s.Profiles[i]
		if p.ID == "" {
			p.ID = "dnsprof-" + shortID()
		}
		cp := p
		m.profiles[cp.ID] = &cp
	}
	m.rules = make(map[string]*api.DnsRule, len(s.Rules))
	for i := range s.Rules {
		r := s.Rules[i]
		if r.ID == "" {
			r.ID = "dnsrule-" + shortID()
		}
		cp := r
		m.rules[cp.ID] = &cp
	}
	if s.Generation != 0 {
		m.lastGen = s.Generation
	}
	return nil
}

func cloneProfiles(in map[string]*api.DnsProfile) []api.DnsProfile {
	out := make([]api.DnsProfile, 0, len(in))
	for _, p := range in {
		out = append(out, *p)
	}
	return out
}

func cloneRules(in map[string]*api.DnsRule) []api.DnsRule {
	out := make([]api.DnsRule, 0, len(in))
	for _, r := range in {
		out = append(out, *r)
	}
	return out
}

// LoadFile reads state from path. Missing file is not an error.
func LoadFile(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

// SaveFile writes snapshot atomically (temp + rename).
func SaveFile(path string, s Snapshot) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	s.Version = snapshotVersion
	s.SavedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Persister debounces disk writes after mutations.
type Persister struct {
	path string
	mem  *Memory
	mu   sync.Mutex
	timer *time.Timer
	delay time.Duration
}

// NewPersister creates a debounced saver. Empty path disables.
func NewPersister(mem *Memory, path string) *Persister {
	return &Persister{path: path, mem: mem, delay: 500 * time.Millisecond}
}

// Path returns the state file path.
func (p *Persister) Path() string { return p.path }

// Enabled reports whether persistence is on.
func (p *Persister) Enabled() bool { return p != nil && p.path != "" }

// Schedule queues a save soon (coalesced).
func (p *Persister) Schedule() {
	if p == nil || p.path == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	p.timer = time.AfterFunc(p.delay, func() {
		_ = p.SaveNow()
	})
}

// SaveNow writes immediately.
func (p *Persister) SaveNow() error {
	if p == nil || p.path == "" {
		return nil
	}
	return SaveFile(p.path, p.mem.Export())
}

// LoadInto loads file into memory if present.
func (p *Persister) LoadInto() error {
	if p == nil || p.path == "" {
		return nil
	}
	s, err := LoadFile(p.path)
	if err != nil {
		return err
	}
	if s.Version == 0 && len(s.Rules) == 0 && len(s.Profiles) == 0 && s.Config.Listeners.UDP == "" {
		return nil
	}
	return p.mem.Import(s)
}
