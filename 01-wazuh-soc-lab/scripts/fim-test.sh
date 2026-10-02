#!/usr/bin/env bash
# =============================================================================
# FIM test: create, modify and delete a file in the monitored folder
# Run on:   ubuntu-endpoint
# Usage:    sudo bash fim-test.sh
#
# Expected alerts on the Wazuh dashboard (agent: ubuntu-endpoint):
#   Without the custom rules:  554 (added) -> 550 (modified)  -> 553 (deleted)
#   With the custom rules:     554 (added) -> 100200 (mod.)   -> 100201 (deleted)
# =============================================================================
set -euo pipefail

FIM_DIR="/opt/fim-lab"
TEST_FILE="${FIM_DIR}/fim-test.txt"
WAIT_SECONDS=10

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo:  sudo bash $0" >&2
  exit 1
fi

if [[ ! -d "$FIM_DIR" ]]; then
  echo "ERROR: $FIM_DIR does not exist. Create it first:  sudo mkdir -p $FIM_DIR" >&2
  exit 1
fi

echo "[1/3] $(date '+%H:%M:%S') Creating  $TEST_FILE   -> expect rule 554 'File added to the system.'"
echo "first line written by fim-test.sh" > "$TEST_FILE"
sleep "$WAIT_SECONDS"

echo "[2/3] $(date '+%H:%M:%S') Modifying $TEST_FILE   -> expect rule 550 (or custom 100200)"
echo "second line added by fim-test.sh" >> "$TEST_FILE"
sleep "$WAIT_SECONDS"

echo "[3/3] $(date '+%H:%M:%S') Deleting  $TEST_FILE   -> expect rule 553 (or custom 100201)"
rm -f "$TEST_FILE"

echo "Done. Check the dashboard: Endpoint security > File Integrity Monitoring > Events"
