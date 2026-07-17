// Package api is the public HTTP contract for dnsd.
// Control plane and dnsctl depend only on this surface.
package api

import "time"

// RuleAction is what happens for a matching name.
type RuleAction string

const (
	ActionAllow    RuleAction = "allow"    // pass to upstream
	ActionBlock    RuleAction = "block"    // NXDOMAIN
	ActionRefuse   RuleAction = "refuse"   // REFUSED
	ActionDrop     RuleAction = "drop"     // no answer
	ActionSinkhole RuleAction = "sinkhole" // fixed A/AAAA
	ActionRewrite  RuleAction = "rewrite"  // CNAME or fixed answers
	ActionForward  RuleAction = "forward"  // specific upstreams
)

// MatchHow names are matched.
type MatchKind string

const (
	MatchExact  MatchKind = "exact"  // www.example.com
	MatchSuffix MatchKind = "suffix" // example.com + subdomains
	MatchGlob   MatchKind = "glob"   // simple * globs
)

// UpstreamProto is how we speak to an upstream resolver.
type UpstreamProto string

const (
	UpstreamDNS UpstreamProto = "dns" // UDP/TCP :53
	UpstreamDoT UpstreamProto = "dot" // DNS-over-TLS :853
	UpstreamDoH UpstreamProto = "doh" // DNS-over-HTTPS
)

// Upstream is one recursive/forward target with optional local bind.
type Upstream struct {
	// Address: host:port, or full URL for DoH (https://dns.google/dns-query).
	// Bare IP → dns://IP:53. "tls://1.1.1.1" → DoT. "https://…" → DoH.
	Address string        `json:"address"`
	Proto   UpstreamProto `json:"proto,omitempty"` // auto from address if empty
	// ServerName for DoT SNI / TLS verify (defaults to host of Address).
	ServerName string `json:"server_name,omitempty"`
	// Outbound: send queries via this source IP or interface.
	BindIP    string `json:"bind_ip,omitempty"`
	BindIface string `json:"bind_iface,omitempty"`
	// Weight for simple weighted pick (0 = 1).
	Weight int `json:"weight,omitempty"`
	// Enabled defaults true when omitted on create.
	Enabled *bool `json:"enabled,omitempty"`
}

// DnsProfile is a named resolver config.
type DnsProfile struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Upstreams     []Upstream `json:"upstreams"`
	SearchDomains []string   `json:"search_domains,omitempty"`
	Default       bool       `json:"default"`
	BlockMalware  bool       `json:"block_malware"`
	Description   string     `json:"description,omitempty"`
	// Outbound defaults for all upstreams in this profile (overridden per-upstream).
	BindIP    string    `json:"bind_ip,omitempty"`
	BindIface string    `json:"bind_iface,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DnsRule is an ordered name policy (block / rewrite / forward).
type DnsRule struct {
	ID       string     `json:"id"`
	Priority int        `json:"priority"` // lower = earlier
	Name     string     `json:"name"`
	Enabled  bool       `json:"enabled"`
	Match    MatchKind  `json:"match"`
	Pattern  string     `json:"pattern"`
	// QTypes: empty = all; else "A","AAAA","CNAME",…
	QTypes  []string   `json:"qtypes,omitempty"`
	Action  RuleAction `json:"action"`
	// Answers for rewrite/sinkhole: IPs or hostnames
	Answers []string `json:"answers,omitempty"`
	// CNAME when Action=rewrite
	CNAME string `json:"cname,omitempty"`
	// TTL for synthetic answers (0 = 60)
	TTL uint32 `json:"ttl,omitempty"`
	// Upstreams when Action=forward
	Upstreams   []Upstream `json:"upstreams,omitempty"`
	Description string     `json:"description,omitempty"`
	HitCount    int64      `json:"hit_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ListenerConfig is data-plane listen settings.
type ListenerConfig struct {
	// Classic DNS
	UDP string `json:"udp,omitempty"` // e.g. 0.0.0.0:53 or 127.0.0.1:5353
	TCP string `json:"tcp,omitempty"`

	// DNS-over-TLS ingress
	DoT     string `json:"dot,omitempty"`      // e.g. 0.0.0.0:853
	DoTCert string `json:"dot_cert,omitempty"` // PEM path
	DoTKey  string `json:"dot_key,omitempty"`

	// DNS-over-HTTPS ingress
	DoH     string `json:"doh,omitempty"` // e.g. 0.0.0.0:443 or 127.0.0.1:8443
	DoHPath string `json:"doh_path,omitempty"` // default /dns-query
	DoHCert string `json:"doh_cert,omitempty"`
	DoHKey  string `json:"doh_key,omitempty"`
	// DoH without TLS (HTTP) — only for local reverse-proxy fronting
	DoHInsecure bool `json:"doh_insecure,omitempty"`
}

// RuntimeConfig is mutable daemon settings.
type RuntimeConfig struct {
	Listeners ListenerConfig `json:"listeners"`
	// Default upstreams when no profile matches
	DefaultUpstreams []Upstream `json:"default_upstreams,omitempty"`
	// Global outbound bind
	BindIP    string `json:"bind_ip,omitempty"`
	BindIface string `json:"bind_iface,omitempty"`
	// CacheTTLMax caps positive cache (seconds); 0 = 300
	CacheTTLMax uint32 `json:"cache_ttl_max,omitempty"`
	// QueryLogSize ring buffer capacity (default 2000)
	QueryLogSize int  `json:"query_log_size,omitempty"`
	Transparent  bool `json:"transparent"`
}

// ProfileCreateRequest creates a profile.
type ProfileCreateRequest struct {
	Name          string     `json:"name"`
	Upstreams     []Upstream `json:"upstreams"`
	// Legacy: plain strings also accepted via Unmarshal helpers in store
	UpstreamAddrs []string `json:"upstream_addrs,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Default       *bool    `json:"default,omitempty"`
	BlockMalware  *bool    `json:"block_malware,omitempty"`
	Description   string   `json:"description,omitempty"`
	BindIP        string   `json:"bind_ip,omitempty"`
	BindIface     string   `json:"bind_iface,omitempty"`
}

// RuleCreateRequest creates a rule.
type RuleCreateRequest struct {
	Priority    int        `json:"priority"`
	Name        string     `json:"name"`
	Enabled     *bool      `json:"enabled,omitempty"`
	Match       MatchKind  `json:"match"`
	Pattern     string     `json:"pattern"`
	QTypes      []string   `json:"qtypes,omitempty"`
	Action      RuleAction `json:"action"`
	Answers     []string   `json:"answers,omitempty"`
	CNAME       string     `json:"cname,omitempty"`
	TTL         uint32     `json:"ttl,omitempty"`
	Upstreams   []Upstream `json:"upstreams,omitempty"`
	Description string     `json:"description,omitempty"`
}

// DesiredState is bulk replace from control plane.
type DesiredState struct {
	Generation int64         `json:"generation"`
	Profiles   []DnsProfile  `json:"profiles,omitempty"`
	Rules      []DnsRule     `json:"rules,omitempty"`
	Config     *RuntimeConfig `json:"config,omitempty"`
	// Legacy fields
	DNSListen   string `json:"dns_listen,omitempty"`
	Transparent *bool  `json:"transparent,omitempty"`
}

// ApplyResult is returned after reconcile / listener (re)start.
type ApplyResult struct {
	OK         bool     `json:"ok"`
	DryRun     bool     `json:"dry_run"`
	Applied    int      `json:"applied"`
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors,omitempty"`
	Commands   []string `json:"commands,omitempty"`
	Message    string   `json:"message,omitempty"`
	Generation int64    `json:"generation,omitempty"`
}

// Status is /v1/status summary.
type Status struct {
	Version        string         `json:"version"`
	Backend        string         `json:"backend"` // live | mock
	ProfileCount   int            `json:"profile_count"`
	RuleCount      int            `json:"rule_count"`
	DNSListen      string         `json:"dns_listen,omitempty"`
	Listeners      ListenerConfig `json:"listeners"`
	// DNSServing is true if UDP or TCP classic DNS is up (compat).
	DNSServing bool `json:"dns_serving"`
	UDPServing bool `json:"udp_serving"`
	TCPServing bool `json:"tcp_serving"` // DNS-over-TCP (RFC 7766), same port as UDP by default
	DoTServing bool `json:"dot_serving"`
	DoHServing bool `json:"doh_serving"`
	Transparent    bool           `json:"transparent"`
	BindIP         string         `json:"bind_ip,omitempty"`
	BindIface      string         `json:"bind_iface,omitempty"`
	LastApplyOK    bool           `json:"last_apply_ok"`
	LastApplyAt    string         `json:"last_apply_at,omitempty"`
	LastGeneration int64          `json:"last_generation"`
	// Live counters
	QueryCount   int64 `json:"query_count"`
	BlockCount   int64 `json:"block_count"`
	RewriteCount int64 `json:"rewrite_count"`
	ErrorCount   int64 `json:"error_count"`
	CacheHits    int64 `json:"cache_hits"`
	CacheMisses  int64 `json:"cache_misses"`
	QPS          float64 `json:"qps"` // recent window
	// Bulk ad/tracker/malware domain sets (--blocklist-dir)
	BlocklistEnabled bool `json:"blocklist_enabled"`
	BlocklistCount   int  `json:"blocklist_count"`
}

// QueryEvent is one resolved query for the live log.
type QueryEvent struct {
	ID        string  `json:"id"`
	Time      string  `json:"time"` // RFC3339Nano
	Client    string  `json:"client"`
	Protocol  string  `json:"protocol"` // udp|tcp|dot|doh
	Name      string  `json:"name"`
	QType     string  `json:"qtype"`
	RCode     string  `json:"rcode"`
	Action    string  `json:"action"` // allow|block|rewrite|sinkhole|forward|cache|error
	Upstream  string  `json:"upstream,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
	Answers   []string `json:"answers,omitempty"`
	Error     string  `json:"error,omitempty"`
	RuleID    string  `json:"rule_id,omitempty"`
	RuleName  string  `json:"rule_name,omitempty"`
	BytesIn   int     `json:"bytes_in,omitempty"`
	BytesOut  int     `json:"bytes_out,omitempty"`
}

// DomainStat is aggregate for a name.
type DomainStat struct {
	Name     string `json:"name"`
	Queries  int64  `json:"queries"`
	Blocks   int64  `json:"blocks"`
	Errors   int64  `json:"errors"`
	LastSeen string `json:"last_seen,omitempty"`
}

// ClientStat is aggregate for a client IP.
type ClientStat struct {
	Client   string `json:"client"`
	Queries  int64  `json:"queries"`
	Blocks   int64  `json:"blocks"`
	Errors   int64  `json:"errors"`
	LastSeen string `json:"last_seen,omitempty"`
}

// StatsSnapshot is /v1/stats.
type StatsSnapshot struct {
	CollectedAt  string  `json:"collected_at"`
	UptimeSec    float64 `json:"uptime_sec"`
	QueryCount   int64   `json:"query_count"`
	BlockCount   int64   `json:"block_count"`
	RewriteCount int64   `json:"rewrite_count"`
	ErrorCount   int64   `json:"error_count"`
	RefuseCount  int64   `json:"refuse_count"`
	DropCount    int64   `json:"drop_count"`
	CacheHits    int64   `json:"cache_hits"`
	CacheMisses  int64   `json:"cache_misses"`
	QPS          float64 `json:"qps"`
	// Breakdowns
	ByRCode   map[string]int64 `json:"by_rcode,omitempty"`
	ByQType   map[string]int64 `json:"by_qtype,omitempty"`
	ByProto   map[string]int64 `json:"by_proto,omitempty"`
	ByAction  map[string]int64 `json:"by_action,omitempty"`
	TopDomains []DomainStat    `json:"top_domains,omitempty"`
	TopBlocked []DomainStat    `json:"top_blocked,omitempty"`
	TopClients []ClientStat    `json:"top_clients,omitempty"`
	RecentErrors []QueryEvent  `json:"recent_errors,omitempty"`
}

// Overview bundles status + objects + stats for TUI.
type Overview struct {
	Status   Status         `json:"status"`
	Config   RuntimeConfig  `json:"config"`
	Profiles []DnsProfile   `json:"profiles"`
	Rules    []DnsRule      `json:"rules"`
	Stats    StatsSnapshot  `json:"stats"`
	// Recent queries (tail of ring)
	Recent []QueryEvent `json:"recent,omitempty"`
}

// VersionInfo is /v1/version.
type VersionInfo struct {
	Version string `json:"version"`
}

// ErrorBody is the standard API error envelope.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ResolveRequest is a one-shot dig-like API.
type ResolveRequest struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // A, AAAA, …
	// Client spoof for policy (optional)
	Client string `json:"client,omitempty"`
}

// ResolveResponse is the dig-like result.
type ResolveResponse struct {
	Event   QueryEvent `json:"event"`
	Message string     `json:"message,omitempty"` // multi-line dig style
}
