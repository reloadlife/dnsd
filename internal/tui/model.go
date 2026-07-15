package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	pkgapi "github.com/reloadlife/dnsd/pkg/api"
)

const (
	tabHome    = 0
	tabLive    = 1 // query log
	tabStats   = 2
	tabRules   = 3
	tabProfiles = 4
	tabConfig  = 5
	tabCount   = 6

	modeList    = 0
	modeForm    = 1
	modeConfirm = 2
)

type rootModel struct {
	cfg    Config
	tab    int
	mode   int
	width  int
	height int

	status   pkgapi.Status
	stats    pkgapi.StatsSnapshot
	profiles []pkgapi.DnsProfile
	rules    []pkgapi.DnsRule
	config   pkgapi.RuntimeConfig
	queries  []pkgapi.QueryEvent

	cursor int
	scroll int

	err        string
	statusLine string
	flash      string
	flashID    int
	busy       bool
	fetchGen   uint64

	// form
	formKind string // rule|profile
	formFields []formField
	formIdx    int
	formErr    string

	confirmText string
	confirmID   string
	confirmKind string // del-rule|del-profile
}

type formField struct {
	label string
	value string
	hint  string
}

type tickMsg time.Time
type flashClearMsg struct{ id int }
type dataMsg struct {
	gen      uint64
	status   pkgapi.Status
	stats    pkgapi.StatsSnapshot
	profiles []pkgapi.DnsProfile
	rules    []pkgapi.DnsRule
	config   pkgapi.RuntimeConfig
	queries  []pkgapi.QueryEvent
	err      error
}
type actionDoneMsg struct {
	err   error
	flash string
}

func newRootModel(cfg Config) rootModel {
	return rootModel{cfg: cfg, statusLine: "connecting…", tab: tabHome}
}

func (m rootModel) Init() tea.Cmd {
	return tea.Batch(fetchAll(m.cfg.Client, m.fetchGen), tickCmd(m.cfg.RefreshInterval))
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func fetchAll(c *pkgapi.Client, gen uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		msg := dataMsg{gen: gen}
		ov, err := c.Overview(ctx)
		if err != nil {
			// fallback
			st, e2 := c.Status(ctx)
			if e2 != nil {
				msg.err = err
				return msg
			}
			msg.status = *st
			if stats, e := c.Stats(ctx); e == nil {
				msg.stats = *stats
			}
			if rules, e := c.ListRules(ctx); e == nil {
				msg.rules = rules
			}
			if profs, e := c.ListProfiles(ctx); e == nil {
				msg.profiles = profs
			}
			if q, e := c.QueryLog(ctx, 200); e == nil {
				msg.queries = q
			}
			if cfg, e := c.Config(ctx); e == nil {
				msg.config = *cfg
			}
			return msg
		}
		msg.status = ov.Status
		msg.stats = ov.Stats
		msg.profiles = ov.Profiles
		msg.rules = ov.Rules
		msg.config = ov.Config
		msg.queries = ov.Recent
		return msg
	}
}

func (m rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		if m.mode == modeList {
			m.fetchGen++
			iv := m.cfg.RefreshInterval
			if m.tab == tabLive || m.tab == tabStats || m.tab == tabHome {
				if iv > time.Second {
					iv = time.Second
				}
			}
			return m, tea.Batch(fetchAll(m.cfg.Client, m.fetchGen), tickCmd(iv))
		}
		return m, tickCmd(m.cfg.RefreshInterval)
	case flashClearMsg:
		if msg.id == m.flashID {
			m.flash = ""
		}
		return m, nil
	case dataMsg:
		if msg.gen != m.fetchGen && msg.gen != 0 {
			// still accept gen 0 init
		}
		if msg.err != nil {
			m.err = msg.err.Error()
			m.statusLine = "error"
		} else {
			m.err = ""
			m.status = msg.status
			m.stats = msg.stats
			m.profiles = msg.profiles
			m.rules = msg.rules
			m.config = msg.config
			m.queries = msg.queries
			m.statusLine = "ok"
			if m.cursor >= m.rowCount() {
				m.cursor = max(0, m.rowCount()-1)
			}
		}
		return m, nil
	case actionDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.err = msg.err.Error()
		} else if msg.flash != "" {
			m.flashID++
			m.flash = msg.flash
			m.fetchGen++
			return m, tea.Batch(
				tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return flashClearMsg{id: m.flashID} }),
				fetchAll(m.cfg.Client, m.fetchGen),
			)
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m rootModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if m.mode == modeConfirm {
		switch key {
		case "y", "Y":
			return m.doConfirm()
		case "n", "N", "esc":
			m.mode = modeList
			return m, nil
		}
		return m, nil
	}
	if m.mode == modeForm {
		return m.handleFormKey(key)
	}
	switch key {
	case "q":
		return m, tea.Quit
	case "1":
		m.tab, m.cursor, m.scroll = tabHome, 0, 0
	case "2":
		m.tab, m.cursor, m.scroll = tabLive, 0, 0
	case "3":
		m.tab, m.cursor, m.scroll = tabStats, 0, 0
	case "4":
		m.tab, m.cursor, m.scroll = tabRules, 0, 0
	case "5":
		m.tab, m.cursor, m.scroll = tabProfiles, 0, 0
	case "6":
		m.tab, m.cursor, m.scroll = tabConfig, 0, 0
	case "tab", "right":
		m.tab = (m.tab + 1) % tabCount
		m.cursor, m.scroll = 0, 0
	case "shift+tab", "left", "h":
		m.tab = (m.tab + tabCount - 1) % tabCount
		m.cursor, m.scroll = 0, 0
	case "j", "down":
		if m.tab == tabHome || m.tab == tabStats || m.tab == tabConfig {
			m.scroll++
		} else if m.cursor < m.rowCount()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.tab == tabHome || m.tab == tabStats || m.tab == tabConfig {
			m.scroll = max(0, m.scroll-1)
		} else if m.cursor > 0 {
			m.cursor--
		}
	case "pgdown":
		m.scroll += 10
		if m.tab == tabLive || m.tab == tabRules {
			m.cursor = min(m.rowCount()-1, m.cursor+10)
		}
	case "pgup":
		m.scroll = max(0, m.scroll-10)
		if m.tab == tabLive || m.tab == tabRules {
			m.cursor = max(0, m.cursor-10)
		}
	case "r":
		m.fetchGen++
		return m, fetchAll(m.cfg.Client, m.fetchGen)
	case "a":
		return m.startAction(func(ctx context.Context, c *pkgapi.Client) error {
			_, err := c.Apply(ctx, false)
			return err
		}, "applied")
	case "n":
		if m.tab == tabRules {
			return m.openRuleForm()
		}
		if m.tab == tabProfiles {
			return m.openProfileForm()
		}
	case "b":
		if m.tab == tabRules || m.tab == tabHome {
			return m.openBlockForm()
		}
	case "w":
		if m.tab == tabRules || m.tab == tabHome {
			return m.openRewriteForm()
		}
	case "D":
		if m.tab == tabRules && m.cursor < len(m.rules) {
			r := m.rules[m.cursor]
			m.confirmKind = "del-rule"
			m.confirmID = r.ID
			m.confirmText = fmt.Sprintf("delete rule %s (%s)?", r.Name, r.Pattern)
			m.mode = modeConfirm
		}
		if m.tab == tabProfiles && m.cursor < len(m.profiles) {
			p := m.profiles[m.cursor]
			m.confirmKind = "del-profile"
			m.confirmID = p.ID
			m.confirmText = fmt.Sprintf("delete profile %s?", p.Name)
			m.mode = modeConfirm
		}
	}
	return m, nil
}

func (m rootModel) rowCount() int {
	switch m.tab {
	case tabLive:
		return len(m.queries)
	case tabRules:
		return len(m.rules)
	case tabProfiles:
		return len(m.profiles)
	default:
		return 0
	}
}

func (m rootModel) startAction(fn func(context.Context, *pkgapi.Client) error, flash string) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	m.busy = true
	c := m.cfg.Client
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := fn(ctx, c)
		return actionDoneMsg{err: err, flash: flash}
	}
}

func (m rootModel) doConfirm() (tea.Model, tea.Cmd) {
	m.mode = modeList
	id := m.confirmID
	kind := m.confirmKind
	return m.startAction(func(ctx context.Context, c *pkgapi.Client) error {
		switch kind {
		case "del-rule":
			return c.DeleteRule(ctx, id)
		case "del-profile":
			return c.DeleteProfile(ctx, id)
		}
		return nil
	}, "deleted")
}

func (m rootModel) View() string {
	w := max(m.width, 60)
	h := max(m.height, 12)
	header := statusStyle.Width(w).Render(fmt.Sprintf(" dnsd  %s  q=%d block=%d err=%d  qps=%.1f  %s %s",
		m.cfg.Endpoint,
		m.status.QueryCount, m.status.BlockCount, m.status.ErrorCount, m.status.QPS,
		servingBadge(m.status),
		m.statusLine,
	))
	if m.flash != "" {
		header = statusStyle.Width(w).Render(" " + m.flash + " ")
	}
	footer := statusStyle.Width(w).Render(" " + m.help() + " ")
	mainH := h - 2
	if mainH < 5 {
		mainH = 5
	}

	var mid string
	if m.mode == modeConfirm {
		mid = panelStyle.Render(m.confirmText + "\n\n" + helpStyle.Render("y confirm · n cancel"))
	} else if m.mode == modeForm {
		mid = m.viewForm()
	} else {
		var b strings.Builder
		b.WriteString(m.renderTabs())
		b.WriteString("\n")
		if m.err != "" {
			b.WriteString(errStyle.Render("error: " + m.err))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		switch m.tab {
		case tabHome:
			b.WriteString(m.viewHome())
		case tabLive:
			b.WriteString(m.viewLive())
		case tabStats:
			b.WriteString(m.viewStats())
		case tabRules:
			b.WriteString(m.viewRules())
		case tabProfiles:
			b.WriteString(m.viewProfiles())
		case tabConfig:
			b.WriteString(m.viewConfig())
		}
		mid = b.String()
	}
	// clip
	lines := strings.Split(mid, "\n")
	if m.scroll > 0 && m.scroll < len(lines) {
		lines = lines[m.scroll:]
	}
	if len(lines) > mainH {
		lines = lines[:mainH]
	}
	for len(lines) < mainH {
		lines = append(lines, "")
	}
	mid = strings.Join(lines, "\n")
	return lipgloss.JoinVertical(lipgloss.Left, header, mid, footer)
}

func servingBadge(st pkgapi.Status) string {
	parts := []string{}
	if st.UDPServing {
		parts = append(parts, badgeUp.Render(" UDP "))
	} else {
		parts = append(parts, badgeDown.Render(" UDP "))
	}
	if st.TCPServing {
		parts = append(parts, badgeUp.Render(" TCP "))
	} else {
		parts = append(parts, badgeDown.Render(" TCP "))
	}
	if st.DoTServing {
		parts = append(parts, badgeUp.Render(" DoT "))
	}
	if st.DoHServing {
		parts = append(parts, badgeUp.Render(" DoH "))
	}
	return strings.Join(parts, "")
}

func (m rootModel) renderTabs() string {
	names := []string{"Home", "Live", "Stats", "Rules", "Profiles", "Config"}
	parts := make([]string, len(names))
	for i, n := range names {
		label := fmt.Sprintf("%d %s", i+1, n)
		if i == m.tab {
			parts[i] = tabActive.Render(label)
		} else {
			parts[i] = tabInactive.Render(label)
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m rootModel) help() string {
	if m.mode == modeForm {
		return "tab fields · enter save · esc cancel"
	}
	if m.mode == modeConfirm {
		return "y/n"
	}
	base := "1-6 tabs · j/k · r refresh · a apply · q quit"
	switch m.tab {
	case tabRules:
		return base + " · n new · b block · w rewrite · D delete"
	case tabProfiles:
		return base + " · n new · D delete"
	case tabLive:
		return "2 Live query log · j/k · r · auto 1s"
	case tabStats:
		return "3 Stats · top domains/clients · r"
	default:
		return base + " · b block · w rewrite"
	}
}

func (m rootModel) viewHome() string {
	st := m.status
	var b strings.Builder
	b.WriteString(titleStyle.Render("dnsd — DNS policy resolver"))
	b.WriteString("\n")
	body := strings.Builder{}
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Version"), valueStyle.Render(st.Version))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("DNS listen"), valueStyle.Render(st.DNSListen))
	fmt.Fprintf(&body, "%s UDP=%v  TCP=%v  DoT=%v  DoH=%v\n", labelStyle.Render("Serving"),
		st.UDPServing, st.TCPServing, st.DoTServing, st.DoHServing)
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Outbound"), valueStyle.Render(first(st.BindIP, st.BindIface, "default route")))
	fmt.Fprintf(&body, "%s %d profiles · %d rules\n", labelStyle.Render("Policy"), st.ProfileCount, st.RuleCount)
	fmt.Fprintf(&body, "\n%s\n", sectionStyle.Render("Live"))
	fmt.Fprintf(&body, "  queries %d   blocks %d   rewrites %d   errors %d\n", st.QueryCount, st.BlockCount, st.RewriteCount, st.ErrorCount)
	fmt.Fprintf(&body, "  qps %.1f   cache hit %d / miss %d\n", st.QPS, st.CacheHits, st.CacheMisses)
	b.WriteString(panelStyle.Render(body.String()))
	b.WriteString("\n\n")
	b.WriteString(sectionStyle.Render("Quick"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  2 Live log · 3 Stats · 4 Rules (b=block w=rewrite) · 5 Profiles · 6 Config"))
	// last few queries
	if len(m.queries) > 0 {
		b.WriteString("\n\n")
		b.WriteString(sectionStyle.Render("Recent queries"))
		b.WriteString("\n")
		start := 0
		if len(m.queries) > 8 {
			start = len(m.queries) - 8
		}
		for _, q := range m.queries[start:] {
			line := fmt.Sprintf("  %-6s %-20s %-6s %-8s %s", trunc(q.Protocol, 6), trunc(q.Name, 20), q.QType, q.Action, q.RCode)
			if q.Action == "block" {
				line = errStyle.Render(line)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (m rootModel) viewLive() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Live query log"))
	b.WriteString(dimStyle.Render(fmt.Sprintf("  ·  %d events  ·  newest at bottom", len(m.queries))))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-8s %-12s %-6s %-28s %-6s %-8s %-8s %s",
		"TIME", "CLIENT", "PROTO", "NAME", "TYPE", "ACTION", "RCODE", "MS")))
	b.WriteString("\n")
	// show last page with cursor
	for i, q := range m.queries {
		t := q.Time
		if len(t) > 8 {
			// use time portion if RFC3339
			if idx := strings.Index(t, "T"); idx >= 0 && len(t) >= idx+9 {
				t = t[idx+1 : idx+9]
			}
		}
		line := fmt.Sprintf("%-8s %-12s %-6s %-28s %-6s %-8s %-8s %.1f",
			trunc(t, 8), trunc(q.Client, 12), trunc(q.Protocol, 6),
			trunc(q.Name, 28), trunc(q.QType, 6), trunc(q.Action, 8), trunc(q.RCode, 8), q.LatencyMs)
		if i == m.cursor {
			line = selStyle.Render(line)
		} else if q.Action == "block" {
			line = errStyle.Render(line)
		} else if q.Action == "error" {
			line = warnStyle.Render(line)
		} else if q.Action == "rewrite" || q.Action == "sinkhole" {
			line = okStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.queries) == 0 {
		b.WriteString(helpStyle.Render("(no queries yet — dig @127.0.0.1 -p 5353 example.com)"))
	}
	return b.String()
}

func (m rootModel) viewStats() string {
	s := m.stats
	var b strings.Builder
	b.WriteString(titleStyle.Render("Statistics"))
	b.WriteString("\n")
	body := strings.Builder{}
	fmt.Fprintf(&body, "queries %d · blocks %d · rewrites %d · errors %d · qps %.2f\n",
		s.QueryCount, s.BlockCount, s.RewriteCount, s.ErrorCount, s.QPS)
	fmt.Fprintf(&body, "cache hit %d miss %d · uptime %.0fs\n", s.CacheHits, s.CacheMisses, s.UptimeSec)
	b.WriteString(panelStyle.Render(body.String()))
	b.WriteString("\n\n")
	b.WriteString(sectionStyle.Render("Top domains"))
	b.WriteString("\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-40s %8s %8s %8s", "NAME", "QUERIES", "BLOCKS", "ERRORS")))
	b.WriteString("\n")
	for _, d := range s.TopDomains {
		if len(b.String()) > 0 {
			// just list
		}
		fmt.Fprintf(&b, "%-40s %8d %8d %8d\n", trunc(d.Name, 40), d.Queries, d.Blocks, d.Errors)
	}
	if len(s.TopDomains) == 0 {
		b.WriteString(dimStyle.Render("(none yet)\n"))
	}
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render("Top blocked"))
	b.WriteString("\n")
	for _, d := range s.TopBlocked {
		fmt.Fprintf(&b, "  %s  ×%d\n", d.Name, d.Blocks)
	}
	if len(s.TopBlocked) == 0 {
		b.WriteString(dimStyle.Render("  (none)\n"))
	}
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render("Top clients"))
	b.WriteString("\n")
	for _, c := range s.TopClients {
		fmt.Fprintf(&b, "  %-20s  q=%d block=%d err=%d\n", c.Client, c.Queries, c.Blocks, c.Errors)
	}
	if len(s.ByRCode) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionStyle.Render("By RCODE / QTYPE / PROTO"))
		b.WriteString("\n")
		fmt.Fprintf(&b, "  rcode %v\n  qtype %v\n  proto %v\n  action %v\n", s.ByRCode, s.ByQType, s.ByProto, s.ByAction)
	}
	if len(s.RecentErrors) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionStyle.Render("Recent errors"))
		b.WriteString("\n")
		start := 0
		if len(s.RecentErrors) > 10 {
			start = len(s.RecentErrors) - 10
		}
		for _, e := range s.RecentErrors[start:] {
			fmt.Fprintf(&b, "  %s %s %s %s\n", trunc(e.Name, 24), e.RCode, e.Action, trunc(e.Error, 40))
		}
	}
	return b.String()
}

func (m rootModel) viewRules() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Rules — block / rewrite / forward"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("n new · b block wizard · w rewrite · D delete"))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-4s %-8s %-8s %-22s %-10s %-8s %s",
		"PRI", "ACTION", "MATCH", "PATTERN", "HITS", "EN", "NAME")))
	b.WriteString("\n")
	for i, r := range m.rules {
		en := "off"
		if r.Enabled {
			en = "on"
		}
		line := fmt.Sprintf("%-4d %-8s %-8s %-22s %-10d %-8s %s",
			r.Priority, r.Action, r.Match, trunc(r.Pattern, 22), r.HitCount, en, trunc(r.Name, 20))
		if i == m.cursor {
			line = selStyle.Render(line)
		} else if r.Action == pkgapi.ActionBlock {
			line = errStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.rules) == 0 {
		b.WriteString(helpStyle.Render("(none — b: block ads.example  ·  w: rewrite app.corp → 10.0.0.1)"))
	}
	return b.String()
}

func (m rootModel) viewProfiles() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Resolver profiles"))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-6s %-16s %-40s %s", "DEF", "NAME", "UPSTREAMS", "BIND")))
	b.WriteString("\n")
	for i, p := range m.profiles {
		def := ""
		if p.Default {
			def = "yes"
		}
		var ups []string
		for _, u := range p.Upstreams {
			ups = append(ups, u.Address)
		}
		bind := first(p.BindIP, p.BindIface, "-")
		line := fmt.Sprintf("%-6s %-16s %-40s %s", def, trunc(p.Name, 16), trunc(strings.Join(ups, ","), 40), bind)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.profiles) == 0 {
		b.WriteString(helpStyle.Render("(none — using default upstreams from config; n to add profile)"))
	}
	return b.String()
}

func (m rootModel) viewConfig() string {
	c := m.config
	var b strings.Builder
	b.WriteString(titleStyle.Render("Config · listeners · outbound"))
	b.WriteString("\n")
	body := strings.Builder{}
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("UDP"), valueStyle.Render(first(c.Listeners.UDP, "-")))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("TCP"), valueStyle.Render(first(c.Listeners.TCP, "-")))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("DoT"), valueStyle.Render(first(c.Listeners.DoT, "off")))
	fmt.Fprintf(&body, "%s %s %s\n", labelStyle.Render("DoH"), valueStyle.Render(first(c.Listeners.DoH, "off")), dimStyle.Render(c.Listeners.DoHPath))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Bind IP"), valueStyle.Render(first(c.BindIP, "-")))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Bind iface"), valueStyle.Render(first(c.BindIface, "-")))
	fmt.Fprintf(&body, "%s %v\n", labelStyle.Render("Transparent"), c.Transparent)
	fmt.Fprintf(&body, "\n%s\n", sectionStyle.Render("Default upstreams"))
	for _, u := range c.DefaultUpstreams {
		fmt.Fprintf(&body, "  [%s] %s", u.Proto, u.Address)
		if u.BindIP != "" || u.BindIface != "" {
			fmt.Fprintf(&body, "  via %s%s", u.BindIP, u.BindIface)
		}
		body.WriteString("\n")
	}
	b.WriteString(panelStyle.Render(body.String()))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Change via API PUT /v1/config or dnsctl config · a = re-apply listeners"))
	return b.String()
}

// forms
func (m rootModel) openBlockForm() (tea.Model, tea.Cmd) {
	m.mode = modeForm
	m.formKind = "block"
	m.formIdx = 0
	m.formErr = ""
	m.formFields = []formField{
		{label: "pattern", value: "", hint: "evil.example or ads.corp"},
		{label: "match", value: "suffix", hint: "exact|suffix|glob"},
		{label: "name", value: "", hint: "optional label"},
	}
	return m, nil
}

func (m rootModel) openRewriteForm() (tea.Model, tea.Cmd) {
	m.mode = modeForm
	m.formKind = "rewrite"
	m.formIdx = 0
	m.formErr = ""
	m.formFields = []formField{
		{label: "pattern", value: "", hint: "app.corp"},
		{label: "answer", value: "", hint: "10.0.0.1 or CNAME host"},
		{label: "match", value: "exact", hint: "exact|suffix"},
		{label: "name", value: "", hint: "optional"},
	}
	return m, nil
}

func (m rootModel) openRuleForm() (tea.Model, tea.Cmd) {
	return m.openBlockForm()
}

func (m rootModel) openProfileForm() (tea.Model, tea.Cmd) {
	m.mode = modeForm
	m.formKind = "profile"
	m.formIdx = 0
	m.formErr = ""
	m.formFields = []formField{
		{label: "name", value: "default", hint: "profile name"},
		{label: "upstreams", value: "1.1.1.1:53,8.8.8.8:53", hint: "csv; DoH https://… DoT tls://1.1.1.1"},
		{label: "bind_ip", value: "", hint: "optional outbound IP"},
		{label: "bind_iface", value: "", hint: "optional outbound iface"},
	}
	return m, nil
}

func (m rootModel) handleFormKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.mode = modeList
		return m, nil
	case "tab", "down", "j":
		if len(m.formFields) > 0 {
			m.formIdx = (m.formIdx + 1) % len(m.formFields)
		}
	case "shift+tab", "up", "k":
		if len(m.formFields) > 0 {
			m.formIdx = (m.formIdx + len(m.formFields) - 1) % len(m.formFields)
		}
	case "enter":
		return m.submitForm()
	case "backspace":
		if len(m.formFields) > 0 {
			v := m.formFields[m.formIdx].value
			if len(v) > 0 {
				m.formFields[m.formIdx].value = v[:len(v)-1]
			}
		}
	default:
		if len(key) == 1 && len(m.formFields) > 0 {
			m.formFields[m.formIdx].value += key
		}
	}
	return m, nil
}

func (m rootModel) viewForm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("New " + m.formKind))
	b.WriteString("\n\n")
	for i, f := range m.formFields {
		line := fmt.Sprintf("%-12s [%s]", f.label, f.value)
		if i == m.formIdx {
			line = selStyle.Render(line) + dimStyle.Render("  "+f.hint)
		} else {
			line = line + dimStyle.Render("  "+f.hint)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if m.formErr != "" {
		b.WriteString("\n")
		b.WriteString(errStyle.Render(m.formErr))
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("type · tab next · enter save · esc cancel"))
	return b.String()
}

func (m rootModel) submitForm() (tea.Model, tea.Cmd) {
	fields := map[string]string{}
	for _, f := range m.formFields {
		fields[f.label] = strings.TrimSpace(f.value)
	}
	kind := m.formKind
	m.mode = modeList
	return m.startAction(func(ctx context.Context, c *pkgapi.Client) error {
		switch kind {
		case "block":
			pat := fields["pattern"]
			if pat == "" {
				return fmt.Errorf("pattern required")
			}
			match := pkgapi.MatchKind(fields["match"])
			if match == "" {
				match = pkgapi.MatchSuffix
			}
			en := true
			_, err := c.CreateRule(ctx, pkgapi.RuleCreateRequest{
				Name: fields["name"], Pattern: pat, Match: match,
				Action: pkgapi.ActionBlock, Enabled: &en, Priority: 50,
			})
			return err
		case "rewrite":
			pat := fields["pattern"]
			ans := fields["answer"]
			if pat == "" || ans == "" {
				return fmt.Errorf("pattern and answer required")
			}
			match := pkgapi.MatchKind(fields["match"])
			if match == "" {
				match = pkgapi.MatchExact
			}
			en := true
			req := pkgapi.RuleCreateRequest{
				Name: fields["name"], Pattern: pat, Match: match,
				Action: pkgapi.ActionRewrite, Enabled: &en, Priority: 40,
			}
			if looksIP(ans) {
				req.Answers = []string{ans}
			} else {
				req.CNAME = ans
			}
			_, err := c.CreateRule(ctx, req)
			return err
		case "profile":
			name := fields["name"]
			if name == "" {
				return fmt.Errorf("name required")
			}
			var ups []pkgapi.Upstream
			for _, p := range strings.Split(fields["upstreams"], ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				ups = append(ups, pkgapi.Upstream{Address: p})
			}
			def := true
			_, err := c.CreateProfile(ctx, pkgapi.ProfileCreateRequest{
				Name: name, Upstreams: ups, Default: &def,
				BindIP: fields["bind_ip"], BindIface: fields["bind_iface"],
			})
			return err
		}
		return nil
	}, "saved")
}

func looksIP(s string) bool {
	return strings.Count(s, ".") == 3 || strings.Contains(s, ":")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
