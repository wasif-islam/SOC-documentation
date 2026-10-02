#!/usr/bin/env bash
# =============================================================================
# SSH brute-force SIMULATION (lab use only, against your own VM)
# Run on:   wazuh-server (it plays the "attacker" for this test)
# Usage:    bash ssh-bruteforce-sim.sh <ENDPOINT_PRIVATE_IP> [ATTEMPTS]
# Example:  bash ssh-bruteforce-sim.sh 10.0.1.20 15
#
# What it does:
#   Tries to log in to ubuntu-endpoint over SSH as a user that does not exist
#   ("badguy"). It never sends a password, so nothing can actually log in.
#
# Expected alerts (agent: ubuntu-endpoint):
#   5710 (level 5)  "sshd: Attempt to login using a non-existent user"  - one per attempt
#   5712 (level 10) "sshd: brute force trying to get access to the system.
#                    Non existent user."  - defined as "5710 seen 8 times from
#                    the same IP within 120 seconds". In practice Wazuh fires
#                    it at about the 10th matching event, so the default
#                    here is 15 attempts.
# =============================================================================
set -uo pipefail   # no "-e": ssh is expected to fail on every attempt

TARGET="${1:-}"
ATTEMPTS="${2:-15}"
FAKE_USER="badguy"

if [[ -z "$TARGET" ]]; then
  echo "Usage: bash $0 <ENDPOINT_PRIVATE_IP> [ATTEMPTS]" >&2
  exit 1
fi

if ! [[ "$ATTEMPTS" =~ ^[0-9]+$ ]] || (( ATTEMPTS < 10 )); then
  echo "ERROR: ATTEMPTS must be a number of at least 10 (rule 5712 needs about 10 events)." >&2
  exit 1
fi

echo "Simulating ${ATTEMPTS} failed SSH logins as '${FAKE_USER}' against ${TARGET}"
for i in $(seq 1 "$ATTEMPTS"); do
  printf '[%02d/%02d] ' "$i" "$ATTEMPTS"
  ssh -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o LogLevel=ERROR \
      "${FAKE_USER}@${TARGET}" true
  sleep 1
done
echo "Done. Check the dashboard: Threat intelligence > Threat Hunting > Events"
