# Security

## Threat model

`dnsd` is a **host DNS policy resolver** plus a **control plane HTTP API**. Compromise of the API means full control of DNS answers for clients using this resolver.

| Surface | Risk | Mitigation |
|---------|------|------------|
| Control API | Auth bypass / RCE via config | Strong Bearer token, loopback or mTLS/TLS, firewall |
| DNS data plane | Amplification, cache poison | Policy engine, upstream TLS (DoT/DoH), query validation |
| State file | Tampering | Root-only path, `0600`/`0640`, integrity via host ACL |
| Metrics | Info leak | Bind metrics with control API; firewall non-loopback |

## Production checklist

1. **Token** — set `DNSD_TOKEN` to a long random secret. Never use `dev-token` outside local dev.
2. **Bind** — keep control API on `127.0.0.1` or private management VLAN. Use `--tls-cert` / `--tls-key` if exposed.
3. **DNS listen** — `:53` only if intended; prefer VPN/client-facing interfaces, not the public internet without rate limiting at the edge.
4. **Upstreams** — prefer DoT/DoH to trusted resolvers; set `bind_ip` / `bind_iface` so recursive traffic exits the intended path.
5. **State file** — `--state-file /var/lib/dnsd/state.json` with directory owned by the service user.
6. **systemd** — use `deploy/dnsd.service` (hardening + `CAP_NET_BIND_SERVICE` only).
7. **Firewall** — allow DNS from clients; allow control API only from management hosts.

## Defaults that are *not* production-safe

| Default | Why |
|---------|-----|
| `dev-token` | Guessable |
| Plain HTTP control API on non-loopback | Credential sniffing |
| No state file | Rules vanish on restart |
| Public UDP/53 open | Abuse / amplification risk if mis-routed |

`dnsd` refuses non-loopback control listen with empty/`dev-token` unless `--allow-insecure` is set.

## Auth

All `/v1/*` routes require:

```
Authorization: Bearer <token>
```

Comparison is constant-time. `/healthz`, `/readyz`, and `/metrics` are unauthenticated by design (use network policy).

## Reporting

Report security issues privately to the repository owner (`reloadlife`).
