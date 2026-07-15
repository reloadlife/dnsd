# dnsd

[![ci](https://github.com/reloadlife/dnsd/actions/workflows/ci.yml/badge.svg)](https://github.com/reloadlife/dnsd/actions/workflows/ci.yml)

Host **DNS resolver / policy** daemon — sister to `wireguardd`, `openvpnd`, `netpolicyd`.

Custom forwarding resolver (miekg/dns) with block / rewrite / forward rules, live stats, query log, and **DoH / DoT** on both ingress and egress. Outbound queries can bind a source **IP** or **interface**.

Companion CLI + TUI: **dnsctl**.

## Features

| Area | Capability |
|------|------------|
| **Listen** | UDP/TCP DNS, DoT (`:853`), DoH (`/dns-query`) |
| **Upstream** | Classic DNS, DoT (`tls://…`), DoH (`https://…/dns-query`) |
| **Outbound** | Per-profile / per-upstream / global `bind_ip` · `bind_iface` |
| **Policy** | block (NXDOMAIN), refuse, drop, sinkhole, rewrite (A/AAAA/CNAME), forward |
| **Telemetry** | QPS, top domains, top blocked, top clients, RCODE/QTYPE/proto, errors |
| **Live log** | Ring buffer of recent queries (API + TUI) |
| **Control** | HTTP API Bearer auth · full Bubble Tea TUI · CLI |

Default control API: **`127.0.0.1:51920`**. Default DNS: **`127.0.0.1:5353`** (safe; use `:53` in production).

## Quick start

```bash
make build
./bin/dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353 \
  --state-file /tmp/dnsd-state.json --allow-insecure

# block + rewrite
./bin/dnsctl block ads.evil
./bin/dnsctl rewrite app.corp 10.77.0.10

# dig through dnsd
dig @127.0.0.1 -p 5353 app.corp +short

# TUI
./bin/dnsctl
```

Env: `DNSD_TOKEN` · `DNSD_STATE_FILE` · `DNSCTL_URL` · `DNSCTL_TOKEN` · `DNSCTL_REFRESH`.

## Production

See [docs/INSTALL.md](docs/INSTALL.md) and [docs/SECURITY.md](docs/SECURITY.md).

- Strong `DNSD_TOKEN` (refuses non-loopback with `dev-token`)
- `--state-file /var/lib/dnsd/state.json` (atomic persist)
- systemd unit with hardening + `CAP_NET_BIND_SERVICE`
- Optional control-API TLS · DoT/DoH listeners · outbound `bind_ip`/`bind_iface`
- `/readyz` reflects live DNS listeners

## TUI tabs

| Key | Tab |
|-----|-----|
| **1 Home** | Status, counters, recent |
| **2 Live** | Live query log (1s refresh) |
| **3 Stats** | Top domains / blocked / clients / errors |
| **4 Rules** | Block & rewrite (`b` / `w` / `n` / `D`) |
| **5 Profiles** | Upstream profiles + bind |
| **6 Config** | Listeners, outbound, default upstreams |

## API (Bearer)

| Method | Path |
|--------|------|
| GET | `/v1/status` · `/v1/overview` · `/v1/stats` · `/v1/queries` |
| GET/PUT | `/v1/config` |
| GET/POST | `/v1/profiles` · `/v1/rules` |
| DELETE | `/v1/profiles/{id}` · `/v1/rules/{id}` |
| POST | `/v1/apply` · `/v1/resolve` · `/v1/desired` |
| GET | `/metrics` · `/healthz` |

See [docs/API.md](docs/API.md).

## Upstream examples

```json
{ "address": "1.1.1.1:53" }
{ "address": "tls://1.1.1.1:853", "server_name": "cloudflare-dns.com", "bind_iface": "wg0" }
{ "address": "https://cloudflare-dns.com/dns-query", "bind_ip": "192.168.20.6" }
```

## Install

```bash
make install   # /usr/local/bin + networkingd daemon dir when present
```

systemd unit: [deploy/dnsd.service](deploy/dnsd.service).

## Docs

| Doc | |
|-----|---|
| [docs/API.md](docs/API.md) | HTTP contract |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Flags, env, listeners, state |
| [docs/TUI.md](docs/TUI.md) | TUI keys |
| [docs/INSTALL.md](docs/INSTALL.md) | Install & production |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model & checklist |
