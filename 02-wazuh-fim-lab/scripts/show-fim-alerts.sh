#!/usr/bin/env bash
# =============================================================================
# Print recent FIM (files and registry) and package (dpkg) alerts from one
# agent, one line each
# Run on:   wazuh-server
# Needs:    jq   (install with: sudo apt-get install -y jq)
# Usage:    sudo bash show-fim-alerts.sh [AGENT_NAME]
# Examples: sudo bash show-fim-alerts.sh ubuntu-endpoint
#           sudo bash show-fim-alerts.sh windows-endpoint
#
# Reads the last SCAN_LINES lines of /var/ossec/logs/alerts/alerts.json
# (default 5000). Change it like this:  sudo SCAN_LINES=20000 bash show-fim-alerts.sh
# =============================================================================
set -euo pipefail

AGENT_NAME="${1:-ubuntu-endpoint}"
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
SCAN_LINES="${SCAN_LINES:-5000}"

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo (the alerts file is readable only by root/wazuh)." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is not installed. Run:  sudo apt-get install -y jq" >&2
  exit 1
fi

tail -n "$SCAN_LINES" "$ALERTS_FILE" | jq -R -c --arg agent "$AGENT_NAME" '
  fromjson?
  | select(.agent.name == $agent)
  | select(.syscheck.path != null or .data.dpkg_status != null)
  | {
      time:    .timestamp,
      rule:    .rule.id,
      level:   .rule.level,
      path:    (.syscheck.path // null),
      value:   (.syscheck.value_name // null),
      event:   (.syscheck.event // null),
      changed: (.syscheck.changed_attributes // null),
      who:     (.syscheck.audit.login_user.name // .syscheck.audit.user.name // null),
      process: (.syscheck.audit.process.name // null),
      package: (if .data.package then "\(.data.dpkg_status) \(.data.package)" else null end)
    }'
