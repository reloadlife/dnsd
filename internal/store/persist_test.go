package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/reloadlife/dnsd/pkg/api"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	m := New()
	en := true
	_, err := m.CreateRule(api.RuleCreateRequest{
		Pattern: "evil.com", Action: api.ActionBlock, Enabled: &en, Match: api.MatchSuffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.CreateProfile(api.ProfileCreateRequest{
		Name: "cf", UpstreamAddrs: []string{"1.1.1.1:53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Config()
	cfg.BindIP = "10.0.0.2"
	m.SetConfig(cfg)
	m.SetLastApply(api.ApplyResult{OK: true}, 42)

	if err := SaveFile(path, m.Export()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		t.Fatal(err)
	}

	m2 := New()
	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m2.Import(s); err != nil {
		t.Fatal(err)
	}
	if len(m2.ListRules()) != 1 || len(m2.ListProfiles()) != 1 {
		t.Fatalf("rules=%d profiles=%d", len(m2.ListRules()), len(m2.ListProfiles()))
	}
	if m2.Config().BindIP != "10.0.0.2" {
		t.Fatal(m2.Config().BindIP)
	}
	_, _, gen := m2.LastApply()
	if gen != 42 {
		// generation set on import
		if gen != 42 {
			// Import sets lastGen
		}
	}
	_, _, gen = m2.LastApply()
	if gen != 42 {
		t.Fatalf("gen %d", gen)
	}
}

func TestPersisterDebounceAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	m := New()
	p := NewPersister(m, path)
	if err := p.LoadInto(); err != nil {
		t.Fatal(err)
	}
	en := true
	_, _ = m.CreateRule(api.RuleCreateRequest{Pattern: "a.com", Action: api.ActionBlock, Enabled: &en})
	if err := p.SaveNow(); err != nil {
		t.Fatal(err)
	}
	m2 := New()
	p2 := NewPersister(m2, path)
	if err := p2.LoadInto(); err != nil {
		t.Fatal(err)
	}
	if len(m2.ListRules()) != 1 {
		t.Fatal(m2.ListRules())
	}
	// disabled
	p3 := NewPersister(m, "")
	if p3.Enabled() {
		t.Fatal()
	}
	if err := p3.SaveNow(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingOK(t *testing.T) {
	s, err := LoadFile(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 0 {
		t.Fatal(s)
	}
}
