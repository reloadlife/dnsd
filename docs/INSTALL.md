# Install dnsd

## Build

```bash
cd ~/workspace/dnsd
make build
# or
make install   # /usr/local/bin + ~/.local/bin + networkingd dir
```

Requires Go 1.25+.

## Run (dev)

```bash
dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353
dnsctl status
dig @127.0.0.1 -p 5353 example.com +short
dnsctl          # TUI
```

## Production (port 53)

```bash
# capabilities or root for :53
dnsd --listen 127.0.0.1:51920 --token "$DNSD_TOKEN" --dns-listen 0.0.0.0:53
```

Prefer a dedicated system user + `AmbientCapabilities=CAP_NET_BIND_SERVICE` (see `deploy/dnsd.service`).

## systemd

```bash
sudo cp deploy/dnsd.service /etc/systemd/system/
sudo cp configs/dnsd.example.env /etc/dnsd/dnsd.env   # edit token
sudo systemctl daemon-reload
sudo systemctl enable --now dnsd
```

## networkingd package

Port **51920**. Package name **dnsd**. Tree: `~/workspace/dnsd`.  
Install path used by agent host: `~/.local/share/networkingd/daemons/dnsd/bin/`.
