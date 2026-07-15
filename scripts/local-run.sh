#!/usr/bin/env bash
# Start/stop local dnsd for interactive testing (dev-token, :5353, state under ~/.local/share/dnsd).
set -euo pipefail

BIN="${DNSD_BIN:-/usr/local/bin/dnsd}"
DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dnsd"
STATE="$DIR/state.json"
LOG="$DIR/dnsd.log"
PIDF="$DIR/dnsd.pid"
LISTEN="${DNSD_LISTEN:-127.0.0.1:51920}"
TOKEN="${DNSD_TOKEN:-dev-token}"
DNS="${DNSD_DNS_LISTEN:-127.0.0.1:5353}"

mkdir -p "$DIR"

cmd="${1:-start}"
case "$cmd" in
  start)
    if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "already running pid=$(cat "$PIDF")"
      exit 0
    fi
    nohup "$BIN" \
      --listen "$LISTEN" \
      --token "$TOKEN" \
      --dns-listen "$DNS" \
      --state-file "$STATE" \
      --upstream "${DNSD_UPSTREAM:-1.1.1.1:53,8.8.8.8:53}" \
      --allow-insecure \
      >"$LOG" 2>&1 &
    echo $! >"$PIDF"
    for _ in $(seq 1 30); do
      curl -sf "http://${LISTEN#}/healthz" >/dev/null 2>&1 && break
      # LISTEN may be host:port
      curl -sf "http://$LISTEN/healthz" >/dev/null 2>&1 && break
      sleep 0.1
    done
    echo "dnsd started pid=$(cat "$PIDF")  api=http://$LISTEN  dns=$DNS  token=$TOKEN"
    echo "  dnsctl status"
    echo "  dig @${DNS%:*} -p ${DNS##*:} example.com +short"
    ;;
  stop)
    if [[ -f "$PIDF" ]]; then
      kill "$(cat "$PIDF")" 2>/dev/null || true
      rm -f "$PIDF"
    fi
    pkill -x dnsd 2>/dev/null || true
    echo "stopped"
    ;;
  status)
    if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "running pid=$(cat "$PIDF")"
      DNSCTL_URL="http://$LISTEN" DNSCTL_TOKEN="$TOKEN" dnsctl status 2>/dev/null || true
    else
      echo "not running"
      exit 1
    fi
    ;;
  restart)
    "$0" stop
    sleep 0.3
    "$0" start
    ;;
  log)
    tail -f "$LOG"
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status|log}"
    exit 2
    ;;
esac
