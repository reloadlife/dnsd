package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client talks to dnsd over HTTP or a Unix socket.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithToken sets the bearer token.
func WithToken(token string) ClientOption {
	return func(c *Client) { c.token = token }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithUnixSocket dials a Unix domain socket.
func WithUnixSocket(socketPath string) ClientOption {
	return func(c *Client) {
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		}
		if c.baseURL == "" {
			c.baseURL = "http://localhost"
		}
	}
}

// NewClient creates an API client.
func NewClient(urlOrUnix string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	if strings.HasPrefix(urlOrUnix, "unix://") {
		path := strings.TrimPrefix(urlOrUnix, "unix://")
		c.baseURL = "http://localhost"
		WithUnixSocket(path)(c)
	} else {
		c.baseURL = strings.TrimRight(urlOrUnix, "/")
	}
	for _, o := range opts {
		o(c)
	}
	if c.baseURL == "" {
		return nil, fmt.Errorf("empty base URL")
	}
	return c, nil
}

// BaseURL returns the configured endpoint.
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil && eb.Error.Message != "" {
			return &APIError{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
		}
		return &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(data))}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Status returns daemon status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Overview returns full TUI snapshot.
func (c *Client) Overview(ctx context.Context) (*Overview, error) {
	var o Overview
	if err := c.do(ctx, http.MethodGet, "/v1/overview", nil, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// Stats returns aggregate statistics.
func (c *Client) Stats(ctx context.Context) (*StatsSnapshot, error) {
	var s StatsSnapshot
	if err := c.do(ctx, http.MethodGet, "/v1/stats", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// QueryLog returns recent queries (limit optional via query string built by caller path).
func (c *Client) QueryLog(ctx context.Context, limit int) ([]QueryEvent, error) {
	path := "/v1/queries"
	if limit > 0 {
		path = fmt.Sprintf("/v1/queries?limit=%d", limit)
	}
	var out []QueryEvent
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Config gets runtime config.
func (c *Client) Config(ctx context.Context) (*RuntimeConfig, error) {
	var cfg RuntimeConfig
	if err := c.do(ctx, http.MethodGet, "/v1/config", nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// PutConfig replaces runtime config and restarts listeners as needed.
func (c *Client) PutConfig(ctx context.Context, cfg RuntimeConfig) (*ApplyResult, error) {
	var res ApplyResult
	if err := c.do(ctx, http.MethodPut, "/v1/config", cfg, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListProfiles lists resolver profiles.
func (c *Client) ListProfiles(ctx context.Context) ([]DnsProfile, error) {
	var out []DnsProfile
	if err := c.do(ctx, http.MethodGet, "/v1/profiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateProfile creates a profile.
func (c *Client) CreateProfile(ctx context.Context, req ProfileCreateRequest) (*DnsProfile, error) {
	var out DnsProfile
	if err := c.do(ctx, http.MethodPost, "/v1/profiles", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteProfile deletes a profile.
func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/profiles/"+id, nil, nil)
}

// ListRules lists DNS rules.
func (c *Client) ListRules(ctx context.Context) ([]DnsRule, error) {
	var out []DnsRule
	if err := c.do(ctx, http.MethodGet, "/v1/rules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateRule creates a rule.
func (c *Client) CreateRule(ctx context.Context, req RuleCreateRequest) (*DnsRule, error) {
	var out DnsRule
	if err := c.do(ctx, http.MethodPost, "/v1/rules", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRule deletes a rule.
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/rules/"+id, nil, nil)
}

// Apply reloads listeners / transparent plan.
func (c *Client) Apply(ctx context.Context, dry bool) (*ApplyResult, error) {
	path := "/v1/apply"
	if dry {
		path += "?dry_run=1"
	}
	var res ApplyResult
	if err := c.do(ctx, http.MethodPost, path, map[string]any{}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Desired bulk-replaces state.
func (c *Client) Desired(ctx context.Context, d DesiredState) (*ApplyResult, error) {
	var res ApplyResult
	if err := c.do(ctx, http.MethodPut, "/v1/desired", d, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Resolve performs a one-shot query through the engine.
func (c *Client) Resolve(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	var out ResolveResponse
	if err := c.do(ctx, http.MethodPost, "/v1/resolve", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Version returns daemon version.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	if err := c.do(ctx, http.MethodGet, "/v1/version", nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
