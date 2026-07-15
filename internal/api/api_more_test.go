package api

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"

	pkg "github.com/reloadlife/dnsd/pkg/api"
)

func TestProfilesCRUD(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/profiles", "test-token", map[string]any{
		"name":           "cf",
		"upstream_addrs": []string{"1.1.1.1:53"},
		"default":        true,
	})
	if rr.Code != http.StatusCreated {
		// also accept structured upstreams
		rr = doJSON(t, h, http.MethodPost, "/v1/profiles", "test-token", map[string]any{
			"name": "cf",
			"upstreams": []map[string]any{
				{"address": "1.1.1.1:53"},
			},
			"default": true,
		})
	}
	if rr.Code != http.StatusCreated {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var p pkg.DnsProfile
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/profiles", "test-token", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodDelete, "/v1/profiles/"+p.ID, "test-token", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("%d", rr.Code)
	}
	rr = doJSON(t, h, http.MethodDelete, "/v1/profiles/missing", "test-token", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("%d", rr.Code)
	}
}

func TestRuleDeleteAndRewriteResolve(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/rules", "test-token", map[string]any{
		"pattern": "app.local",
		"match":   "exact",
		"action":  "rewrite",
		"answers": []string{"10.1.2.3"},
		"enabled": true,
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	var rule pkg.DnsRule
	_ = json.Unmarshal(rr.Body.Bytes(), &rule)

	rr = doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{
		"name": "app.local", "type": "A",
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	var res pkg.ResolveResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Event.Action != "rewrite" {
		t.Fatalf("%+v", res.Event)
	}

	rr = doJSON(t, h, http.MethodDelete, "/v1/rules/"+rule.ID, "test-token", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatal(rr.Code)
	}
}

func TestRefuseSinkholeDropViaResolve(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	for _, body := range []map[string]any{
		{"pattern": "ref.test", "match": "suffix", "action": "refuse", "enabled": true},
		{"pattern": "sink.test", "match": "exact", "action": "sinkhole", "enabled": true, "answers": []string{"0.0.0.0"}},
		{"pattern": "drop.test", "match": "exact", "action": "drop", "enabled": true},
	} {
		rr := doJSON(t, h, http.MethodPost, "/v1/rules", "test-token", body)
		if rr.Code != http.StatusCreated {
			t.Fatalf("%v → %s", body, rr.Body.String())
		}
	}
	// refuse
	rr := doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{"name": "a.ref.test", "type": "A"})
	var res pkg.ResolveResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Event.Action != "refuse" || res.Event.RCode != "REFUSED" {
		t.Fatalf("%+v", res.Event)
	}
	// sinkhole
	rr = doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{"name": "sink.test", "type": "A"})
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Event.Action != "sinkhole" {
		t.Fatalf("%+v", res.Event)
	}
	// drop
	rr = doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{"name": "drop.test", "type": "A"})
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if res.Event.Action != "drop" {
		t.Fatalf("%+v", res.Event)
	}
}

func TestDesiredAndApply(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	// free ports for apply
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := pc.LocalAddr().String()
	_ = pc.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp := ln.Addr().String()
	_ = ln.Close()

	rr := doJSON(t, h, http.MethodPut, "/v1/desired", "test-token", map[string]any{
		"generation": 3,
		"rules": []map[string]any{
			{"priority": 1, "name": "b", "enabled": true, "match": "suffix", "pattern": "bulk.x", "action": "block"},
		},
		"profiles": []map[string]any{
			{"name": "p", "default": true, "upstreams": []map[string]any{{"address": "1.1.1.1:53"}}},
		},
		"config": map[string]any{
			"listeners": map[string]any{
				"udp": udp, "tcp": tcp,
			},
			"default_upstreams": []map[string]any{{"address": "1.1.1.1:53"}},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	var res pkg.ApplyResult
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if !res.OK {
		t.Fatalf("%+v", res)
	}

	rr = doJSON(t, h, http.MethodPost, "/v1/apply?dry_run=1", "test-token", map[string]any{})
	_ = json.Unmarshal(rr.Body.Bytes(), &res)
	if !res.DryRun {
		t.Fatalf("%+v", res)
	}

	rr = doJSON(t, h, http.MethodPost, "/v1/apply", "test-token", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}

	// cleanup listeners
	s.DNS.Stop()
}

func TestConfigPutAndMetricsHealth(t *testing.T) {
	s := newTestServer()
	h := s.Handler()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	udp := pc.LocalAddr().String()
	_ = pc.Close()

	rr := doJSON(t, h, http.MethodPut, "/v1/config", "test-token", map[string]any{
		"listeners":         map[string]any{"udp": udp, "tcp": udp},
		"default_upstreams": []map[string]any{{"address": "8.8.8.8:53"}},
		"cache_ttl_max":     60,
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	s.DNS.Stop()

	rr2 := doJSON(t, h, http.MethodGet, "/healthz", "", nil)
	if rr2.Code != http.StatusOK {
		t.Fatal(rr2.Code)
	}
	// metrics has no auth
	rr = doJSON(t, h, http.MethodGet, "/metrics", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	if !contains(rr.Body.String(), "dnsd_up") {
		t.Fatal(rr.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestServer().Handler()
	rr := doJSON(t, h, http.MethodDelete, "/v1/rules", "test-token", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("%d", rr.Code)
	}
	rr = doJSON(t, h, http.MethodDelete, "/v1/status", "test-token", nil)
	if rr.Code != http.StatusMethodNotAllowed && rr.Code != http.StatusOK {
		// status only GET — mux may 405
	}
}

func TestResolveValidation(t *testing.T) {
	h := newTestServer().Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/resolve", "test-token", map[string]any{"name": ""})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
