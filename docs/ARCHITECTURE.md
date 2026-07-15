# How dnsd works

`dnsd` is a Linux **DNS policy resolver** daemon. It answers DNS queries according to configured rules, forwards the rest to upstream resolvers, and exposes live stats over an HTTP control API. The companion binary `dnsctl` is a TUI/CLI client for that API.

## Components

```
dnsctl  ── HTTP (Bearer) ──►  dnsd control API (:51920)
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
               memory/state    telemetry    DNS data plane
            (rules, profiles,  (query log,   (UDP / TCP /
             config, JSON)      stats)        DoT / DoH)
                    │                           │
                    └────────── engine ◄────────┘
                                  │
                            upstreams
                      (dns / DoT / DoH + bind)
```

| Piece | Role |
|-------|------|
| **Control API** | CRUD for rules/profiles/config; apply; resolve; stats; query log |
| **Store** | In-memory desired state; optional JSON `--state-file` persistence |
| **Engine** | Match name → block/rewrite/forward/allow → upstream or synthetic answer |
| **Listeners** | Classic DNS **UDP + TCP**, optional DoT and DoH ingress |
| **Telemetry** | Ring buffer of queries, counters, top domains/clients, QPS |
| **dnsctl** | Full-screen TUI + CLI against the API |

## Query path

1. Client sends a query (UDP, TCP, DoT, or DoH).
2. Engine normalizes the QNAME and validates length/class.
3. Enabled rules are evaluated by priority (exact / suffix / glob; optional QTYPE filter).
4. First match wins:
   - **block** → NXDOMAIN  
   - **refuse** → REFUSED  
   - **drop** → no response  
   - **sinkhole / rewrite** → synthetic A/AAAA/CNAME  
   - **forward** → specific upstream list  
   - **allow** → fall through  
5. If no terminal rule: check response cache, else query default profile / global upstreams.
6. Classic upstreams try **UDP**, then **TCP** on truncation or failure. DoT/DoH use TLS/HTTPS.
7. Outbound dial may bind a source **IP** or **interface** (`bind_ip` / `bind_iface`).
8. Result is recorded in telemetry (action, RCODE, latency, upstream).

## Data plane vs control plane

- **Data plane** — ports that speak DNS (default `127.0.0.1:5353` UDP+TCP).  
- **Control plane** — HTTP API (default `127.0.0.1:51920`) with Bearer auth. Not used by recursive clients.

`/healthz` means process up. `/readyz` means at least one classic DNS listener (UDP or TCP) is serving.

## Persistence

With `--state-file`, rules, profiles, and runtime config are written atomically (temp + rename), debounced after API mutations, and flushed on SIGTERM. Without a state file, state is process-local only.

## Related binaries

| Binary | Purpose |
|--------|---------|
| `dnsd` | Daemon |
| `dnsctl` | Operator TUI/CLI |

Default ports: API **51920**, DNS **5353** (use **53** in production with appropriate capabilities).
