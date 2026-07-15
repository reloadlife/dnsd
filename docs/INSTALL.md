# Install dnsd

## Build

```bash
make build
# or
make install   # /usr/local/bin + ~/.local/bin + networkingd dir when present
```

Requires Go 1.25+. See [ARCHITECTURE.md](ARCHITECTURE.md) for how the daemon works.

## Run (dev)

```bash
dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353 --allow-insecure
# or with persistence:
dnsd --state-file /tmp/dnsd-state.json --token dev-token --allow-insecure

dnsctl status
dig @127.0.0.1 -p 5353 example.com +short
dnsctl          # TUI
```

## Production (recommended)

```bash
# user + data dir
sudo useradd --system --home /var/lib/dnsd --shell /usr/sbin/nologin dnsd
sudo mkdir -p /var/lib/dnsd /etc/dnsd
sudo chown dnsd:dnsd /var/lib/dnsd

# binary
sudo install -m 755 bin/dnsd bin/dnsctl /usr/local/bin/

# env (edit token!)
sudo cp configs/dnsd.example.env /etc/dnsd/dnsd.env
sudo chmod 600 /etc/dnsd/dnsd.env
sudo $EDITOR /etc/dnsd/dnsd.env

# unit
sudo cp deploy/dnsd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnsd
sudo systemctl status dnsd
```

### Port 53

```bash
# in /etc/dnsd/dnsd.env
DNSD_DNS_LISTEN=0.0.0.0:53
```

The unit grants `CAP_NET_BIND_SERVICE` so the `dnsd` user can bind privileged ports without running as root.

### Persistence

With `DNSD_STATE_FILE=/var/lib/dnsd/state.json`, rules/profiles/config survive restarts. Writes are atomic (temp + rename) and debounced after API mutations; a final save runs on SIGTERM.

### Health

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | process up |
| `GET /readyz` | DNS UDP or TCP listener is serving (503 otherwise) |
| `GET /metrics` | Prometheus counters |

### Firewall sketch

```bash
# clients → DNS
# nft/iptables: allow udp/tcp dport 53 from VPN/LAN

# management → API only from admin net
# allow tcp 51920 from 10.0.0.0/8 to 127.0.0.1 via SSH tunnel preferred
```

## networkingd package

Port **51920**. Package name **dnsd**. Tree: `~/workspace/dnsd`.  
Agent path: `~/.local/share/networkingd/daemons/dnsd/bin/`.

## Flags / env

See [CONFIGURATION.md](CONFIGURATION.md) and [SECURITY.md](SECURITY.md).
