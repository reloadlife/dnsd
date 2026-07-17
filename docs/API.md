# dnsd HTTP API

Base URL default: `http://127.0.0.1:51920`

All `/v1/*` routes require:

```
Authorization: Bearer <token>
```

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET | `/healthz` | open |
| GET | `/v1/version` | `{ "version": "…" }` |
| GET | `/v1/status` | serving flags (udp/tcp/dot/doh), counters, QPS, blocklist_count |
| GET | `/v1/overview` | status + config + rules + profiles + stats + recent queries |
| GET | `/v1/stats` | aggregates: top domains/blocked/clients, by rcode/qtype/proto |
| GET | `/v1/queries?limit=N` | ring buffer (newest last) |
| GET/PUT | `/v1/config` | listeners, default upstreams, bind, transparent |
| GET/POST | `/v1/profiles` | resolver profiles |
| DELETE | `/v1/profiles/{id}` | |
| GET/POST | `/v1/rules` | block / rewrite / forward |
| DELETE | `/v1/rules/{id}` | |
| GET | `/v1/blocklists` | bulk ad/malware sets: `{ enabled, count, sources }` |
| POST | `/v1/blocklists` | reload from `--blocklist-dir` without restart |
| PUT/POST | `/v1/desired` | bulk replace + apply |
| POST | `/v1/apply?dry_run=1` | (re)start listeners |
| POST | `/v1/resolve` | dig-like through engine |
| GET | `/metrics` | Prometheus text |

## Rule create

```json
{
  "priority": 50,
  "name": "block-ads",
  "enabled": true,
  "match": "suffix",
  "pattern": "ads.evil",
  "action": "block"
}
```

Actions: `allow` · `block` · `refuse` · `drop` · `sinkhole` · `rewrite` · `forward`  
Match: `exact` · `suffix` · `glob`

Rewrite / sinkhole:

```json
{
  "match": "exact",
  "pattern": "app.corp",
  "action": "rewrite",
  "answers": ["10.77.0.10"],
  "ttl": 60
}
```

Or `"cname": "internal.corp"`.

Forward:

```json
{
  "match": "suffix",
  "pattern": "corp.internal",
  "action": "forward",
  "upstreams": [
    { "address": "10.0.0.53:53", "bind_iface": "lan0" }
  ]
}
```

## Profile create

```json
{
  "name": "vpn-out",
  "default": true,
  "upstreams": [
    { "address": "tls://1.1.1.1:853", "server_name": "cloudflare-dns.com" },
    { "address": "https://dns.google/dns-query" }
  ],
  "bind_ip": "192.168.20.6"
}
```

Address prefixes: bare IP → classic DNS :53 (UDP then TCP) · `tls://` / `dot://` → DoT · `https://` → DoH · `dns://` → UDP/TCP.

## Classic DNS (UDP + TCP)

Ingress and status:

| Field | Meaning |
|-------|---------|
| `listeners.udp` | DNS-over-UDP listen address |
| `listeners.tcp` | DNS-over-TCP listen address (RFC 7766; usually same host:port as UDP) |
| `udp_serving` / `tcp_serving` | live listener state |
| `dns_serving` | true if either UDP or TCP is up |

`--dns-listen` sets **both** UDP and TCP. Overrides: `--dns-udp` / `--dns-tcp` (or `DNSD_DNS_UDP` / `DNSD_DNS_TCP`).

Query log `protocol` values: `udp` · `tcp` · `dot` · `doh` · `api`.

Upstream classic DNS tries **UDP first**, retries **TCP** on truncation or UDP failure.

## Config

```json
{
  "listeners": {
    "udp": "0.0.0.0:53",
    "tcp": "0.0.0.0:53",
    "dot": "0.0.0.0:853",
    "dot_cert": "/etc/dnsd/tls.crt",
    "dot_key": "/etc/dnsd/tls.key",
    "doh": "127.0.0.1:8443",
    "doh_path": "/dns-query",
    "doh_insecure": true
  },
  "default_upstreams": [
    { "address": "1.1.1.1:53" }
  ],
  "bind_ip": "",
  "bind_iface": "",
  "cache_ttl_max": 300,
  "query_log_size": 2000,
  "transparent": false
}
```

## Resolve

```json
POST /v1/resolve
{ "name": "example.com", "type": "A", "client": "10.0.0.5" }
```

## Query event

```json
{
  "id": "…",
  "time": "2026-07-15T12:00:00.123Z",
  "client": "10.77.0.4",
  "protocol": "udp",
  "name": "example.com",
  "qtype": "A",
  "rcode": "NOERROR",
  "action": "allow",
  "upstream": "dns://1.1.1.1:53",
  "latency_ms": 12.4,
  "answers": ["example.com. 300 IN A 93.184.216.34"]
}
```

Actions: `allow` · `block` · `rewrite` · `sinkhole` · `forward` · `cache` · `error` · `refuse` · `drop`.
