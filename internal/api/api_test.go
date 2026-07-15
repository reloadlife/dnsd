package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reloadlife/dnsd/internal/resolve"
	"github.com/reloadlife/dnsd/internal/store"
	pkg "github.com/reloadlife/dnsd/pkg/api"
)

func newTestServer() *Server {
	st := store.New()
	tel := resolve.NewTelemetry(100)
	eng := resolve.NewEngine(st, tel)
	dns := resolve.NewServer(eng)
	return &Server{Store: st, Engine: eng, DNS: dns, Token: "test-token", Version: "test"}
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAuthAndStatus(t *testing.T) {
	h := newTestServer().Handler()
	rr := doJSON(t, h, http.MethodGet, "/v1/status", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", rr.Code)
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/status", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}
}

func TestRulesAndResolveBlock(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/rules", "test-token", map[string]any{
		"pattern": "blocked.test",
		"match":   "suffix",
		"action":  "block",
		"enabled": true,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{
		"name": "x.blocked.test",
		"type": "A",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve %d %s", rr.Code, rr.Body.String())
	}
	var res pkg.ResolveResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Event.Action != "block" {
		t.Fatalf("action %s", res.Event.Action)
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/stats", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/queries?limit=10", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
}

func TestOverviewAndConfig(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	rr := doJSON(t, h, http.MethodGet, "/v1/overview", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/config", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
}
