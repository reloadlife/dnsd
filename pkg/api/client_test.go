package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClientAndAPIError(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("empty url")
	}
	c, err := NewClient("http://example.com", WithToken("t"))
	if err != nil || c.BaseURL() != "http://example.com" {
		t.Fatal(err, c)
	}
	ae := &APIError{Status: 401, Code: "unauthorized", Message: "nope"}
	if ae.Error() == "" {
		t.Fatal()
	}
	ae2 := &APIError{Status: 500, Message: "x"}
	if ae2.Error() == "" {
		t.Fatal()
	}
}

func TestClientAgainstMux(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(ErrorBody{Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "unauthorized", Message: "bad"}})
			return
		}
		_ = json.NewEncoder(w).Encode(Status{Version: "t", Backend: "live", DNSServing: true})
	})
	mux.HandleFunc("/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode([]DnsRule{{ID: "1", Pattern: "x", Action: ActionBlock}})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(DnsRule{ID: "2", Pattern: "y", Action: ActionRewrite})
		default:
			w.WriteHeader(405)
		}
	})
	mux.HandleFunc("/v1/rules/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(405)
	})
	mux.HandleFunc("/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]DnsProfile{})
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(DnsProfile{ID: "p1", Name: "n"})
	})
	mux.HandleFunc("/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(StatsSnapshot{QueryCount: 3})
	})
	mux.HandleFunc("/v1/queries", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]QueryEvent{{Name: "a.com", Action: "allow"}})
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(RuntimeConfig{})
			return
		}
		_ = json.NewEncoder(w).Encode(ApplyResult{OK: true})
	})
	mux.HandleFunc("/v1/overview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Overview{Status: Status{Version: "t"}})
	})
	mux.HandleFunc("/v1/apply", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ApplyResult{OK: true, DryRun: r.URL.Query().Get("dry_run") == "1"})
	})
	mux.HandleFunc("/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ResolveResponse{Event: QueryEvent{Action: "block", Name: "x"}})
	})
	mux.HandleFunc("/v1/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(VersionInfo{Version: "1"})
	})
	mux.HandleFunc("/v1/desired", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ApplyResult{OK: true, Generation: 9})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := NewClient(ts.URL, WithToken("tok"), WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := c.Status(ctx)
	if err != nil || !st.DNSServing {
		t.Fatal(err, st)
	}
	// bad token
	cBad, _ := NewClient(ts.URL, WithToken("nope"), WithHTTPClient(ts.Client()))
	if _, err := cBad.Status(ctx); err == nil {
		t.Fatal("expected auth error")
	}

	if _, err := c.ListRules(ctx); err != nil {
		t.Fatal(err)
	}
	en := true
	if _, err := c.CreateRule(ctx, RuleCreateRequest{Pattern: "z", Action: ActionBlock, Enabled: &en}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteRule(ctx, "2"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListProfiles(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateProfile(ctx, ProfileCreateRequest{Name: "n", UpstreamAddrs: []string{"1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stats(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.QueryLog(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Config(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutConfig(ctx, RuntimeConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Overview(ctx); err != nil {
		t.Fatal(err)
	}
	if res, err := c.Apply(ctx, true); err != nil || !res.DryRun {
		t.Fatal(err, res)
	}
	if _, err := c.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resolve(ctx, ResolveRequest{Name: "x", Type: "A"}); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Version(ctx); err != nil || v.Version != "1" {
		t.Fatal(err, v)
	}
	if _, err := c.Desired(ctx, DesiredState{Generation: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestUnixClientOption(t *testing.T) {
	c, err := NewClient("unix:///tmp/dnsd.sock", WithToken("t"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "http://localhost" {
		t.Fatal(c.BaseURL())
	}
}
