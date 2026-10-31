#!/usr/bin/env bash
# LogSentinel agent: ships the last N minutes of sshd auth events to the API and,
# optionally, blocks IPs the model flags. Designed to run from the systemd timer.
#
#   LOGSENTINEL_API=https://xxxx.execute-api.us-east-1.amazonaws.com ./logsentinel-agent.sh
#
# Env:
#   LOGSENTINEL_API      API base URL (required)
#   LOGSENTINEL_SINCE    journalctl --since window (default "15 min ago")
#   LOGSENTINEL_ENFORCE  1 = add `ufw deny` rules for "block" verdicts (default 0, report only)
set -euo pipefail

API="${LOGSENTINEL_API:?set LOGSENTINEL_API}"
SINCE="${LOGSENTINEL_SINCE:-15 min ago}"
ENFORCE="${LOGSENTINEL_ENFORCE:-0}"
HOST="$(hostname -s)"
log() { logger -t logsentinel "$*"; echo "[logsentinel] $*" >&2; }

for bin in curl jq; do command -v "$bin" >/dev/null || { log "missing dependency: $bin"; exit 2; }; done

# Prefer the journal (systemd distros); fall back to the classic file.
if command -v journalctl >/dev/null && journalctl -q -n0 -u ssh -u sshd >/dev/null 2>&1; then
  LOGS="$(journalctl -u ssh -u sshd --since "$SINCE" -o short-iso --no-pager 2>/dev/null || true)"
elif [[ -r /var/log/auth.log ]]; then
  LOGS="$(tail -n 5000 /var/log/auth.log)"
else
  LOGS="$(tail -n 5000 /var/log/secure 2>/dev/null || true)"
fi

if [[ -z "${LOGS//[$'\t\r\n ']}" ]]; then
  log "no sshd events since '$SINCE'"; exit 0
fi

REPORT="$(jq -n --arg log "$LOGS" --arg host "$HOST" --argjson year "$(date +%Y)" \
  '{log: $log, host: $host, year: $year, save: true}' |
  curl -fsS --max-time 20 -H 'Content-Type: application/json' -d @- "$API/analyze")"

ID="$(jq -r .id <<<"$REPORT")"
read -r EVENTS BLOCKED SUSP < <(jq -r '.summary | "\(.events) \(.blocked) \(.suspicious)"' <<<"$REPORT")
log "report=$ID events=$EVENTS block=$BLOCKED suspicious=$SUSP"

if [[ "$ENFORCE" == "1" && "$BLOCKED" -gt 0 ]]; then
  command -v ufw >/dev/null || { log "ENFORCE=1 but ufw not installed"; exit 3; }
  jq -r '.results[] | select(.verdict=="block") | .ip' <<<"$REPORT" | while read -r ip; do
    if ! ufw status | grep -q "$ip"; then
      ufw deny from "$ip" comment "logsentinel $ID" >/dev/null && log "blocked $ip"
    fi
  done
fi
