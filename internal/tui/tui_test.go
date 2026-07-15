package tui

import (
	"testing"
	"time"

	pkgapi "github.com/reloadlife/dnsd/pkg/api"
)

func TestTruncAndHelpers(t *testing.T) {
	if trunc("hello", 10) != "hello" {
		t.Fatal()
	}
	if trunc("hello-world", 5) != "hell…" && trunc("hello-world", 5) != "hello" {
		// our trunc uses ellipsis when n>1
		got := trunc("hello-world", 5)
		if len(got) > 5 {
			t.Fatal(got)
		}
	}
	if first("", "b", "c") != "b" {
		t.Fatal()
	}
	if max(1, 2) != 2 || min(1, 2) != 1 {
		t.Fatal()
	}
	if !looksIP("1.2.3.4") {
		t.Fatal()
	}
}

func TestRowCountAndViews(t *testing.T) {
	m := rootModel{
		tab: tabLive,
		queries: []pkgapi.QueryEvent{
			{Name: "a.com", Action: "allow", Protocol: "udp", QType: "A", RCode: "NOERROR"},
			{Name: "b.com", Action: "block", Protocol: "udp", QType: "A", RCode: "NXDOMAIN"},
		},
		rules: []pkgapi.DnsRule{
			{Name: "r1", Action: pkgapi.ActionBlock, Pattern: "x", Enabled: true},
		},
		profiles: []pkgapi.DnsProfile{{Name: "p"}},
		status: pkgapi.Status{
			Version: "t", QueryCount: 2, BlockCount: 1, DNSServing: true,
		},
		stats: pkgapi.StatsSnapshot{
			QueryCount: 2,
			TopDomains: []pkgapi.DomainStat{{Name: "a.com", Queries: 2}},
			TopBlocked: []pkgapi.DomainStat{{Name: "b.com", Blocks: 1}},
			TopClients: []pkgapi.ClientStat{{Client: "1.1.1.1", Queries: 2}},
			ByRCode:    map[string]int64{"NOERROR": 1},
			ByAction:   map[string]int64{"allow": 1, "block": 1},
		},
		config: pkgapi.RuntimeConfig{
			Listeners: pkgapi.ListenerConfig{UDP: "127.0.0.1:5353"},
			DefaultUpstreams: []pkgapi.Upstream{{Address: "1.1.1.1:53", Proto: pkgapi.UpstreamDNS}},
		},
		width: 120, height: 40,
	}
	if m.rowCount() != 2 {
		t.Fatal(m.rowCount())
	}
	m.tab = tabRules
	if m.rowCount() != 1 {
		t.Fatal(m.rowCount())
	}
	m.tab = tabProfiles
	if m.rowCount() != 1 {
		t.Fatal()
	}
	// views should not panic
	for _, tab := range []int{tabHome, tabLive, tabStats, tabRules, tabProfiles, tabConfig} {
		m.tab = tab
		_ = m.viewHome()
		_ = m.viewLive()
		_ = m.viewStats()
		_ = m.viewRules()
		_ = m.viewProfiles()
		_ = m.viewConfig()
		_ = m.renderTabs()
		_ = m.help()
	}
	_ = servingBadge(m.status)
	_ = m.View()
}

func TestNewRootModelInit(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://x", RefreshInterval: time.Second})
	if m.tab != tabHome || m.statusLine == "" {
		t.Fatalf("%+v", m)
	}
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("expected init cmd")
	}
}

func TestFormOpen(t *testing.T) {
	m := newRootModel(Config{})
	tm, _ := m.openBlockForm()
	rm := tm.(rootModel)
	if rm.mode != modeForm || len(rm.formFields) == 0 {
		t.Fatal()
	}
	tm, _ = m.openRewriteForm()
	rm = tm.(rootModel)
	if rm.formKind != "rewrite" {
		t.Fatal(rm.formKind)
	}
	tm, _ = m.openProfileForm()
	rm = tm.(rootModel)
	if rm.formKind != "profile" {
		t.Fatal()
	}
}
