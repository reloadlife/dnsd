package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/reloadlife/dnsd/internal/resolve"
	"github.com/reloadlife/dnsd/internal/store"
	pkg "github.com/reloadlife/dnsd/pkg/api"
)

// Server is the dnsd HTTP control API.
type Server struct {
	Store   *store.Memory
	Engine  *resolve.Engine
	DNS     *resolve.Server
	Persist *store.Persister
	Token   string
	Version string
}

// Handler returns the HTTP mux with production middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/v1/version", s.auth(s.version))
	mux.HandleFunc("/v1/status", s.auth(s.status))
	mux.HandleFunc("/v1/overview", s.auth(s.overview))
	mux.HandleFunc("/v1/stats", s.auth(s.stats))
	mux.HandleFunc("/v1/queries", s.auth(s.queries))
	mux.HandleFunc("/v1/config", s.auth(s.config))
	mux.HandleFunc("/v1/profiles", s.auth(s.profiles))
	mux.HandleFunc("/v1/profiles/", s.auth(s.profileOne))
	mux.HandleFunc("/v1/rules", s.auth(s.rules))
	mux.HandleFunc("/v1/rules/", s.auth(s.ruleOne))
	mux.HandleFunc("/v1/desired", s.auth(s.desired))
	mux.HandleFunc("/v1/apply", s.auth(s.apply))
	mux.HandleFunc("/v1/resolve", s.auth(s.resolveOne))
	mux.HandleFunc("/v1/blocklists", s.auth(s.blocklists))
	mux.HandleFunc("/metrics", s.metrics)
	return s.wrap(mux)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !bearerOK(r.Header.Get("Authorization"), s.Token) {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		next(w, r)
	}
}

func (s *Server) touch() {
	if s.Persist != nil {
		s.Persist.Schedule()
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "service": "dnsd"})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	udp, tcp, _, _ := s.DNS.State()
	if !udp && !tcp {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "reason": "dns listeners down",
		})
		return
	}
	writeJSON(w, map[string]string{"status": "ready", "service": "dnsd"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"version": s.Version})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.buildStatus())
}

func (s *Server) buildStatus() pkg.Status {
	last, at, gen := s.Store.LastApply()
	cfg := s.Store.Config()
	q, b, rw, er, ch, cm := s.Engine.Tel.Counters()
	udp, tcp, dot, doh := s.DNS.State()
	st := pkg.Status{
		Version:        s.Version,
		Backend:        "live",
		ProfileCount:   len(s.Store.ListProfiles()),
		RuleCount:      len(s.Store.ListRules()),
		DNSListen:      s.Store.DNSListen(),
		Listeners:      cfg.Listeners,
		DNSServing:     udp || tcp,
		UDPServing:     udp,
		TCPServing:     tcp,
		DoTServing:     dot,
		DoHServing:     doh,
		Transparent:    cfg.Transparent,
		BindIP:         cfg.BindIP,
		BindIface:      cfg.BindIface,
		LastApplyOK:    last.OK,
		LastApplyAt:    formatTime(at),
		LastGeneration: gen,
		QueryCount:     q,
		BlockCount:     b,
		RewriteCount:   rw,
		ErrorCount:     er,
		CacheHits:      ch,
		CacheMisses:    cm,
		QPS:            s.Engine.Tel.QPS(),
	}
	if bl := s.Engine.Blocklist; bl != nil {
		st.BlocklistEnabled = true
		st.BlocklistCount = bl.Count()
	}
	return st
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, pkg.Overview{
		Status:   s.buildStatus(),
		Config:   s.Store.Config(),
		Profiles: s.Store.ListProfiles(),
		Rules:    s.Store.ListRules(),
		Stats:    s.Engine.Tel.Snapshot(),
		Recent:   s.Engine.Tel.Recent(100),
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.Engine.Tel.Snapshot())
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}
	writeJSON(w, s.Engine.Tel.Recent(limit))
}

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.Config())
	case http.MethodPut, http.MethodPost:
		var cfg pkg.RuntimeConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		s.Store.SetConfig(cfg)
		res := s.doApply(false)
		s.touch()
		writeJSON(w, res)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListProfiles())
	case http.MethodPost:
		var req pkg.ProfileCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		p, err := s.Store.CreateProfile(req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.touch()
		writeJSONStatus(w, http.StatusCreated, p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) profileOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/profiles/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteProfile(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.touch()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListRules())
	case http.MethodPost:
		var req pkg.RuleCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		rule, err := s.Store.CreateRule(req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.touch()
		writeJSONStatus(w, http.StatusCreated, rule)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ruleOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/rules/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteRule(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.touch()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) desired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var d pkg.DesiredState
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	if d.Profiles != nil {
		s.Store.ReplaceProfiles(d.Profiles)
	}
	if d.Rules != nil {
		s.Store.ReplaceRules(d.Rules)
	}
	if d.Config != nil {
		s.Store.SetConfig(*d.Config)
	}
	if d.DNSListen != "" {
		s.Store.SetDNSListen(d.DNSListen)
	}
	if d.Transparent != nil {
		s.Store.SetTransparent(*d.Transparent)
	}
	res := s.doApply(false)
	res.Generation = d.Generation
	s.Store.SetLastApply(res, d.Generation)
	s.touch()
	writeJSON(w, res)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	dry := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	res := s.doApply(dry)
	if !dry {
		s.touch()
	}
	writeJSON(w, res)
}

// blocklists: GET status · POST reload from configured --blocklist-dir.
func (s *Server) blocklists(w http.ResponseWriter, r *http.Request) {
	bl := s.Engine.Blocklist
	switch r.Method {
	case http.MethodGet:
		if bl == nil {
			writeJSON(w, map[string]any{"enabled": false, "count": 0, "sources": []string{}})
			return
		}
		writeJSON(w, map[string]any{
			"enabled": true,
			"count":   bl.Count(),
			"sources": bl.Sources(),
		})
	case http.MethodPost:
		if bl == nil {
			writeErr(w, http.StatusBadRequest, "no_blocklist", "blocklist not configured (--blocklist-dir)")
			return
		}
		n, err := bl.Reload()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "reload_failed", err.Error())
			return
		}
		writeJSON(w, map[string]any{
			"ok":      true,
			"count":   n,
			"sources": bl.Sources(),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) doApply(dry bool) pkg.ApplyResult {
	cfg := s.Store.Config()
	cmds := resolve.PlanApply(cfg)
	res := pkg.ApplyResult{
		OK:       true,
		DryRun:   dry,
		Commands: cmds,
		Message:  "listeners ready",
	}
	if dry {
		res.Skipped = len(cmds)
		res.Message = "dry-run: listeners not restarted"
		return res
	}
	if err := s.DNS.Start(cfg.Listeners); err != nil {
		res.OK = false
		res.Errors = append(res.Errors, err.Error())
		res.Message = "listener start errors"
	} else {
		res.Applied = len(cmds)
		udp, tcp, dot, doh := s.DNS.State()
		res.Message = fmt.Sprintf("udp=%v tcp=%v dot=%v doh=%v", udp, tcp, dot, doh)
	}
	_, _, gen := s.Store.LastApply()
	s.Store.SetLastApply(res, gen)
	return res
}

func (s *Server) resolveOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req pkg.ResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name required")
		return
	}
	qtype := dns.TypeA
	if req.Type != "" {
		if t, ok := dns.StringToType[strings.ToUpper(req.Type)]; ok {
			qtype = t
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	client := req.Client
	if client == "" {
		client = "api"
	}
	resp, ev := s.Engine.Handle(r.Context(), m, client, "api")
	s.Engine.Tel.Record(ev)
	out := pkg.ResolveResponse{Event: ev}
	if resp != nil {
		var b strings.Builder
		fmt.Fprintf(&b, ";; %s %s → %s (%s) %.2fms\n", ev.Name, ev.QType, ev.RCode, ev.Action, ev.LatencyMs)
		for _, a := range resp.Answer {
			fmt.Fprintf(&b, "%s\n", a.String())
		}
		out.Message = b.String()
	}
	writeJSON(w, out)
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	st := s.buildStatus()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, `# HELP dnsd_up 1 if control API up
# TYPE dnsd_up gauge
dnsd_up 1
# TYPE dnsd_profiles gauge
dnsd_profiles %d
# TYPE dnsd_rules gauge
dnsd_rules %d
# TYPE dnsd_queries_total counter
dnsd_queries_total %d
# TYPE dnsd_blocks_total counter
dnsd_blocks_total %d
# TYPE dnsd_errors_total counter
dnsd_errors_total %d
# TYPE dnsd_qps gauge
dnsd_qps %f
# TYPE dnsd_serving gauge
dnsd_serving %d
`, st.ProfileCount, st.RuleCount, st.QueryCount, st.BlockCount, st.ErrorCount, st.QPS, boolToInt(st.DNSServing))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": errCode, "message": msg},
	})
}
