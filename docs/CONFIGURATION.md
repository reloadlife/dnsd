# dnsd configuration

## Daemon flags & env

Every flag has a matching `DNSD_*` environment variable (flag wins when both set).

```bash
dnsd \
  --listen 127.0.0.1:51920 \
  --token "$DNSD_TOKEN" \
  --dns-listen 127.0.0.1:5353 \
  --state-file /var/lib/dnsd/state.json \
  --bind-ip 192.168.20.6 \
  --bind-iface wg0 \
  --upstream '1.1.1.1:53,https://1.1.1.1/dns-query'
```

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--listen` | `DNSD_LISTEN` | `127.0.0.1:51920` | Control API |
| `--token` | `DNSD_TOKEN` | *(required in prod)* | Bearer secret |
| `--dns-listen` | `DNSD_DNS_LISTEN` | `127.0.0.1:5353` | classic DNS UDP **and** TCP (same addr) |
| `--dns-udp` | `DNSD_DNS_UDP` | *(same as dns-listen)* | UDP-only override |
| `--dns-tcp` | `DNSD_DNS_TCP` | *(same as dns-listen)* | TCP-only override (set empty to disable TCP) |
| `--bind-ip` | `DNSD_BIND_IP` | empty | outbound source IP |
| `--bind-iface` | `DNSD_BIND_IFACE` | empty | outbound iface (`SO_BINDTODEVICE`) |
| `--upstream` | `DNSD_UPSTREAM` | `1.1.1.1:53,8.8.8.8:53` | CSV default upstreams |
| `--state-file` | `DNSD_STATE_FILE` | empty | durable JSON state |
| `--blocklist-dir` | `DNSD_BLOCKLIST_DIR` | empty | dir of `*.txt` / hosts files (ad/tracker/malware) |
| `--tls-cert` | `DNSD_TLS_CERT` | empty | control API TLS cert |
| `--tls-key` | `DNSD_TLS_KEY` | empty | control API TLS key |
| `--allow-insecure` | `DNSD_ALLOW_INSECURE` | false | allow empty/`dev-token` on non-loopback |
| `--shutdown-timeout` | — | `10s` | graceful stop |

### Safety

- Non-loopback `--listen` with empty or `dev-token` **refuses to start** unless `--allow-insecure`.
- Prefer loopback control API + SSH tunnel, or TLS certs.

## Runtime config (API)

`PUT /v1/config` updates listeners (UDP/TCP/DoT/DoH), default upstreams, binds, cache, log size, transparent plan. Apply restarts DNS listeners and persists when `--state-file` is set.

### Listeners

| Field | Example |
|-------|---------|
| `udp` | `0.0.0.0:53` — DNS-over-UDP |
| `tcp` | `0.0.0.0:53` — DNS-over-TCP (same port is normal; required for large answers / RFC 7766) |
| `dot` | `0.0.0.0:853` + `dot_cert` / `dot_key` |
| `doh` | `127.0.0.1:8443` + optional cert or `doh_insecure: true` |
| `doh_path` | `/dns-query` |

### Outbound path selection

1. Per-upstream `bind_ip` / `bind_iface`
2. Profile `bind_ip` / `bind_iface`
3. Global config / CLI flags

### State file format

```json
{
  "version": 1,
  "saved_at": "2026-07-15T18:00:00Z",
  "generation": 3,
  "config": { "listeners": { "udp": "127.0.0.1:5353", "tcp": "127.0.0.1:5353" }, "...": "..." },
  "profiles": [],
  "rules": []
}
```

Written atomically (`*.tmp` + rename). Debounced ~500ms after mutations; flushed on SIGTERM.

## Transparent redirect (plan only)

When `transparent: true`, apply returns `nft` redirect commands. Host agent / operator executes them.

## CLI env

| Env | Default |
|-----|---------|
| `DNSCTL_URL` | `http://127.0.0.1:51920` |
| `DNSCTL_TOKEN` | `dev-token` |
| `DNSCTL_REFRESH` | `1s` |

## Example env files

`configs/dnsd.example.env` · `configs/dnsctl.example.env`
