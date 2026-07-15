# dnsctl TUI

```bash
dnsctl                 # default
dnsctl tui
DNSCTL_URL=http://127.0.0.1:51920 DNSCTL_TOKEN=dev-token dnsctl
```

Requires a real TTY.

## Tabs

| Key | Tab | Contents |
|-----|-----|----------|
| **1** | Home | Status, counters, recent queries |
| **2** | Live | Full query log (auto ~1s) |
| **3** | Stats | Top domains, blocked, clients, RCODE, errors |
| **4** | Rules | Policy list · create/delete |
| **5** | Profiles | Upstream profiles |
| **6** | Config | Listeners + outbound |

## Keys

| Key | Action |
|-----|--------|
| `1`–`6` / tab | Switch tab |
| `j` `k` | Move / scroll |
| `r` | Refresh |
| `a` | Apply (restart listeners) |
| `n` | New rule/profile |
| `b` | Block wizard |
| `w` | Rewrite wizard |
| `D` | Delete (confirm `y`) |
| `q` | Quit |

## Live log columns

TIME · CLIENT · PROTO · NAME · TYPE · ACTION · RCODE · latency ms

Actions colored: block (red), rewrite (green), error (yellow).

## Stats

- **Top domains** — most queried names  
- **Top blocked** — most blocked  
- **Top clients** — busiest client IPs  
- **By RCODE / QTYPE / PROTO / ACTION**  
- **Recent errors** — SERVFAIL / action=error  

This is the primary operator surface for “what is being resolved right now?”
