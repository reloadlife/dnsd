#!/bin/bash
# Fetch ad / tracking / malware / phishing blocklists for dnsd.
# Safe formats: bare domains, hosts (0.0.0.0 domain), *.wildcards.
set -euo pipefail

DIR="${DNSD_BLOCKLIST_DIR:-/var/lib/dnsd/blocklists}"
API="${DNSD_API:-http://127.0.0.1:51920}"
TOKEN="${DNSD_TOKEN:-}"
mkdir -p "$DIR"
cd "$DIR"
UA='dnsd-blocklists/1.0 (+https://github.com/reloadlife/dnsd)'

fetch() {
  local out="$1" url="$2"
  if curl -fsSL --max-time 180 --retry 2 -A "$UA" -o "${out}.tmp" "$url"; then
    # skip empty / tiny failures
    if [[ $(wc -c <"${out}.tmp") -lt 64 ]]; then
      echo "skip $out (too small)"
      rm -f "${out}.tmp"
      return 0
    fi
    mv "${out}.tmp" "$out"
    echo "ok $out ($(wc -l <"$out") lines)"
  else
    rm -f "${out}.tmp"
    echo "fail $out ($url)" >&2
  fi
}

echo "=== dnsd blocklist refresh $(date -u +%Y-%m-%dT%H:%MZ) ==="

# --- Ads ---
fetch oisd-small.txt \
  "https://small.oisd.nl/domainswild"
fetch 1hosts-lite.txt \
  "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt"
fetch adguard-dns.txt \
  "https://v.firebog.net/hosts/AdguardDNS.txt"
fetch prigent-ads.txt \
  "https://v.firebog.net/hosts/Prigent-Ads.txt"
fetch admiral.txt \
  "https://v.firebog.net/hosts/Admiral.txt"

# --- Tracking / telemetry / privacy ---
fetch easyprivacy.txt \
  "https://v.firebog.net/hosts/Easyprivacy.txt"
fetch windows-spy.txt \
  "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
fetch fade-2o7net.txt \
  "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts"

# --- Combined ads+malware baseline ---
fetch stevenblack-hosts.txt \
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

# --- Malware / phishing / cryptominers ---
fetch urlhaus-hosts.txt \
  "https://urlhaus.abuse.ch/downloads/hostfile/"
fetch nocoin.txt \
  "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
fetch phishing-army.txt \
  "https://phishing.army/download/phishing_army_blocklist_extended.txt"

# Minimal always-on fallback if fetches fail
if [[ ! -s ads-fallback.txt ]]; then
  cat > ads-fallback.txt <<'EOF'
# local fallback ad/tracker seeds
doubleclick.net
googleadservices.com
googlesyndication.com
google-analytics.com
googletagmanager.com
facebook.net
scorecardresearch.com
hotjar.com
EOF
fi

echo "--- loaded files ---"
ls -lh "$DIR"/*.txt 2>/dev/null | awk '{print $5, $9}'
echo "--- unique domain estimate (approx lines) ---"
wc -l "$DIR"/*.txt 2>/dev/null | tail -1

# Hot-reload dnsd without restart (POST /v1/blocklists)
reload_dnsd() {
  local tok="${TOKEN}"
  if [[ -z "$tok" && -f /opt/networkingd/configs/dnsd.env ]]; then
    # shellcheck disable=SC1091
    tok=$(grep -E '^DNSD_TOKEN=' /opt/networkingd/configs/dnsd.env | cut -d= -f2- || true)
  fi
  if [[ -z "$tok" && -f /etc/dnsd/dnsd.env ]]; then
    tok=$(grep -E '^DNSD_TOKEN=' /etc/dnsd/dnsd.env | cut -d= -f2- || true)
  fi
  if [[ -z "$tok" ]]; then
    echo "warn: no DNSD_TOKEN — restart dnsd to pick up lists (or export DNSD_TOKEN)"
    systemctl try-reload-or-restart dnsd.service networkingd-dnsd.service 2>/dev/null || true
    return 0
  fi
  local code
  code=$(curl -sS -o /tmp/dnsd-bl-reload.json -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $tok" \
    "${API%/}/v1/blocklists" 2>/dev/null || echo 000)
  if [[ "$code" == "200" ]]; then
    echo "reload ok: $(cat /tmp/dnsd-bl-reload.json)"
  else
    echo "reload http=$code — try restarting dnsd"
    systemctl restart dnsd.service networkingd-dnsd.service 2>/dev/null || true
    sleep 1
    curl -sS -X POST -H "Authorization: Bearer $tok" \
      "${API%/}/v1/blocklists" 2>/dev/null || true
    echo
  fi
}

reload_dnsd
echo "DONE"
