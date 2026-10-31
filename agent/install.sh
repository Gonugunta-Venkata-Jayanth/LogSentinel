#!/usr/bin/env bash
# sudo ./install.sh https://<your-api-url>   -- installs agent + systemd timer
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
API="${1:?usage: install.sh <api-url> [enforce:0|1]}"
DIR="$(cd "$(dirname "$0")" && pwd)"
install -m 0755 "$DIR/logsentinel-agent.sh" /usr/local/bin/logsentinel-agent.sh
install -m 0644 "$DIR/logsentinel.service" "$DIR/logsentinel.timer" /etc/systemd/system/
printf 'LOGSENTINEL_API=%s\nLOGSENTINEL_ENFORCE=%s\n' "$API" "${2:-0}" > /etc/default/logsentinel
systemctl daemon-reload
systemctl enable --now logsentinel.timer
echo "installed. logs: journalctl -t logsentinel -f"
