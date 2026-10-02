#!/usr/bin/env bash
# =============================================================================
# Print recent Wazuh alerts for one or more rule IDs, one line per alert
# Run on:   wazuh-server
# Needs:    jq   (install with: sudo apt install -y jq)
# Usage:    sudo bash show-alerts.sh <RULE_ID> [RULE_ID ...]
# Examples: sudo bash show-alerts.sh 550 553 554
#           sudo bash show-alerts.sh 5710 5712
#
# Reads the last SCAN_LINES lines of /var/ossec/logs/alerts/alerts.json
# (default 5000). Change it like this:  sudo SCAN_LINES=20000 bash show-alerts.sh 5712
# =============================================================================
set -euo pipefail

ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
SCAN_LINES="${SCAN_LINES:-5000}"

if [[ $# -eq 0 ]]; then
  echo "Usage: sudo bash $0 <RULE_ID> [RULE_ID ...]" >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo (the alerts file is readable only by root/wazuh)." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is not installed. Run:  sudo apt install -y jq" >&2
  exit 1
fi

IDS_JSON=$(printf '%s\n' "$@" | jq -R . | jq -s -c .)

tail -n "$SCAN_LINES" "$ALERTS_FILE" | jq -R -c --argjson ids "$IDS_JSON" '
  fromjson?
  | select(.rule.id | IN($ids[]))
  | {
      time:        .timestamp,
      agent:       .agent.name,
      rule:        .rule.id,
      level:       .rule.level,
      description: .rule.description,
      mitre:       (.rule.mitre.id // []),
      srcip:       (.data.srcip // null),
      file:        (.syscheck.path // null)
    }'
