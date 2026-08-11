# dnsd

[![ci](https://github.com/reloadlife/dnsd/actions/workflows/ci.yml/badge.svg)](https://github.com/reloadlife/dnsd/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/reloadlife/dnsd)](https://github.com/reloadlife/dnsd/releases)

**dnsd** is a Linux **DNS policy resolver** daemon: it applies block/rewrite/forward rules, answers or forwards queries (UDP, TCP, DoT, DoH), and exposes live stats over HTTP.

**dnsctl** is the control panel: full-screen TUI plus CLI.

How it works: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Features

| Area | Capability |
|------|------------|
| **Listen** | Classic DNS **UDP + TCP** (RFC 1035/7766), DoT, DoH |
| **Upstream** | DNS (UDP→TCP fallback), DoT (`tls://…`), DoH (`https://…`) |
| **Outbound** | Per-profile / per-upstream / global `bind_ip` · `bind_iface` |
| **Policy** | block, refuse, drop, sinkhole, rewrite, forward |
| **Blocklists** | Bulk ad/tracker/malware domain sets (`--blocklist-dir`, NXDOMAIN) |
| **Client ACL** | `allow_cidrs` — who may query at all (empty = everyone) |
| **SNI relay** | Hijack a domain to this host in DNS, then relay its TLS/HTTP out a chosen interface |
| **Telemetry** | QPS, top domains/blocked/clients, query log, errors |
| **Control** | Bearer HTTP API · Bubble Tea TUI · CLI |
| **State** | Optional JSON `--state-file` (atomic, survives restart) |

Default control API: **`127.0.0.1:51920`**. Default DNS: **`127.0.0.1:5353`**.

## Quick start

```bash
make build
./bin/dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353 \
  --state-file /tmp/dnsd-state.json --allow-insecure

export DNSCTL_URL=http://127.0.0.1:51920 DNSCTL_TOKEN=dev-token
./bin/dnsctl block ads.evil
./bin/dnsctl rewrite app.corp 10.77.0.10
dig @127.0.0.1 -p 5353 app.corp +short
dig @127.0.0.1 -p 5353 app.corp +tcp +short
./bin/dnsctl   # TUI
```

### Ad / tracker blocklists

```bash
# fetch OISD, 1Hosts, EasyPrivacy, StevenBlack, URLhaus, …
export DNSD_BLOCKLIST_DIR=/var/lib/dnsd/blocklists
export DNSD_TOKEN=dev-token
./scripts/refresh-blocklists.sh

# run with bulk lists (NXDOMAIN for matches + parent suffixes)
./bin/dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353 \
  --blocklist-dir "$DNSD_BLOCKLIST_DIR" --allow-insecure

# hot-reload after refresh
curl -X POST -H "Authorization: Bearer dev-token" http://127.0.0.1:51920/v1/blocklists
```

## SNI relay ("smart DNS")

Two halves of one list. A route makes dnsd answer that name with **this host's**
addresses, and makes the relay carry the resulting connection to the real origin
over a chosen exit interface.

```bash
curl -X PUT -H "Authorization: Bearer $DNSD_TOKEN" http://127.0.0.1:51920/v1/sni -d '{
  "enabled": true,
  "listen_tls": "0.0.0.0:443",
  "listen_http": "0.0.0.0:80",
  "allow_cidrs": ["195.24.237.0/24"],
  "answers": ["195.24.237.4"],
  "resolvers": ["1.1.1.1:53"],
  "fallback": "127.0.0.1:8443",
  "fallback_proxy_proto": true,
  "routes": [{"pattern": "docker.com", "match": "suffix", "enabled": true, "bind_iface": "eth1"}]
}'
```

Rules that matter:

- **`resolvers` must not point at this dnsd.** The hijack would resolve the name
  to this host and the relay would dial itself. Rejected at config time.
- **AAAA is answered NODATA** for hijacked names, so dual-stack clients cannot
  reach the origin directly and bypass the relay.
- **Nothing is ever rejected on the listener.** Unknown SNI, absent SNI, or a
  client outside `allow_cidrs` all go to `fallback` untouched — that port is
  usually shared with a VPN server, and refusing would take it down. Set
  `fallback_proxy_proto` so the backend still sees the real client IP
  (ocserv: `listen-proxy-proto = true`).
- `allow_cidrs` here gates **relaying**; the top-level `allow_cidrs` in
  `/v1/config` gates **DNS** and is normally the wider list.

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How dnsd works |
| [docs/API.md](docs/API.md) | HTTP API |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Flags, env, listeners, state |
| [docs/TUI.md](docs/TUI.md) | TUI tabs and keys |
| [docs/INSTALL.md](docs/INSTALL.md) | Install and production |
| [docs/SECURITY.md](docs/SECURITY.md) | Hardening checklist |

Example env: [`configs/`](configs/) · systemd: [`deploy/dnsd.service`](deploy/dnsd.service)

## Donations

If this project is useful to you, donations are welcome:

| Network | Address |
|---------|---------|
| **Bitcoin** (BTC) | `bc1qy08pk2teys968hphh98rv8y9azeraf2c8vsdm8` |
| **EVM** (ETH, BNB, USDT, and other EVM chains) | `0x8B6CE1EA8F17f6941F13A621b92Af345a75D8c41` |
| **TRON** (TRX) | `TGXJToyAsUtw1388jR5aW9ZohjSCDtmKbg` |

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

If you run a modified version of `dnsd` as a network service, you must offer the corresponding source to users who interact with it over the network (AGPL §13).
