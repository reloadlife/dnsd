# dnsd configuration

## Daemon flags

```bash
dnsd \
  --listen 127.0.0.1:51920 \
  --token dev-token \
  --dns-listen 127.0.0.1:5353 \
  --bind-ip 192.168.20.6 \
  --bind-iface wg0 \
  --upstream '1.1.1.1:53,tls://1.1.1.1,https://cloudflare-dns.com/dns-query'
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen` | `127.0.0.1:51920` | HTTP control API |
| `--token` | `dev-token` | Bearer token |
| `--dns-listen` | `127.0.0.1:5353` | UDP+TCP DNS |
| `--bind-ip` | empty | default outbound source IP |
| `--bind-iface` | empty | default outbound interface (Linux `SO_BINDTODEVICE`) |
| `--upstream` | `1.1.1.1:53,8.8.8.8:53` | CSV default upstreams |

## Runtime config (API)

`PUT /v1/config` updates listeners (UDP/TCP/DoT/DoH), default upstreams, binds, cache, log size, transparent plan. Apply restarts DNS listeners.

### Listeners

| Field | Example |
|-------|---------|
| `udp` / `tcp` | `0.0.0.0:53` or `127.0.0.1:5353` |
| `dot` | `0.0.0.0:853` + `dot_cert` / `dot_key` |
| `doh` | `127.0.0.1:8443` + optional cert or `doh_insecure: true` |
| `doh_path` | `/dns-query` |

### Outbound path selection

Priority for source address of upstream queries:

1. Per-upstream `bind_ip` / `bind_iface`
2. Profile `bind_ip` / `bind_iface` (when using profile upstreams)
3. Global config / `--bind-ip` / `--bind-iface`

Use this to force recursive queries out a VPN tunnel interface while still answering on the LAN.

## Transparent redirect (plan only)

When `transparent: true`, apply returns `nft` commands to redirect client UDP/TCP :53 to the local listen port. Execution is left to the operator / host agent (same pattern as netpolicyd dry-run commands).

## CLI env

| Env | Default |
|-----|---------|
| `DNSCTL_URL` | `http://127.0.0.1:51920` |
| `DNSCTL_TOKEN` | `dev-token` |
| `DNSCTL_REFRESH` | `1s` |

## Example env files

See `configs/dnsd.example.env` and `configs/dnsctl.example.env`.
