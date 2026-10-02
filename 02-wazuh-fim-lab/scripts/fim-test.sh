#!/usr/bin/env bash
# =============================================================================
# FIM setup test for Linux: makes every change type the setup must detect
# Run on:   ubuntu-endpoint, after the FIM setup steps are finished
# Usage:    sudo bash fim-test.sh
#
# Steps and the alerts each one must produce (agent: ubuntu-endpoint):
#   1. create a file              -> 554  File added to the system.
#   2. add a line to it           -> 550  Integrity checksum changed. (size, mtime, md5, sha1, sha256)
#   3. chmod 600                  -> 550  (permission)
#   4. chown nobody:nogroup       -> 550  (uid, user_name, gid, group_name)
#   5. delete it                  -> 553  File deleted.
#   6. useradd fimtest            -> 550  for /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow (and their "-" backups)
#   7. userdel fimtest            -> 550  for the same files
#   8. create /etc/cron.d/fim-lab-test (comment only, runs nothing) -> 554
#   9. delete it                  -> 553
#  10. apt-get install hello      -> 554  for /usr/bin/hello, and dpkg rules 2901, 2904, 2902
#  11. apt-get remove hello       -> 553  for /usr/bin/hello, and dpkg rule 2903
# =============================================================================
set -euo pipefail

FIM_DIR="/opt/fim-lab"
TEST_FILE="${FIM_DIR}/fim-test.txt"
CRON_FILE="/etc/cron.d/fim-lab-test"
TEST_USER="fimtest"
WAIT_SECONDS=10

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo:  sudo bash $0" >&2
  exit 1
fi

if [[ ! -d "$FIM_DIR" ]]; then
  echo "ERROR: $FIM_DIR does not exist. Create it first:  sudo mkdir -p $FIM_DIR" >&2
  exit 1
fi

if id "$TEST_USER" >/dev/null 2>&1; then
  echo "ERROR: user '$TEST_USER' already exists. Remove it first:  sudo userdel $TEST_USER" >&2
  exit 1
fi

step() { echo "[$1/11] $(date '+%H:%M:%S') $2"; }

step 1 "Create    $TEST_FILE"
echo "first line" > "$TEST_FILE"
sleep "$WAIT_SECONDS"

step 2 "Modify    $TEST_FILE (add a line)"
echo "second line" >> "$TEST_FILE"
sleep "$WAIT_SECONDS"

step 3 "chmod 600 $TEST_FILE"
chmod 600 "$TEST_FILE"
sleep "$WAIT_SECONDS"

step 4 "chown nobody:nogroup $TEST_FILE"
chown nobody:nogroup "$TEST_FILE"
sleep "$WAIT_SECONDS"

step 5 "Delete    $TEST_FILE"
rm -f "$TEST_FILE"
sleep "$WAIT_SECONDS"

step 6 "Add user  $TEST_USER (no home folder, no login shell)"
useradd -M -s /usr/sbin/nologin "$TEST_USER"
sleep "$WAIT_SECONDS"

step 7 "Delete user $TEST_USER"
userdel "$TEST_USER"
sleep "$WAIT_SECONDS"

step 8 "Create    $CRON_FILE (a comment only, it runs nothing)"
echo "# FIM lab test file, safe to delete" > "$CRON_FILE"
sleep "$WAIT_SECONDS"

step 9 "Delete    $CRON_FILE"
rm -f "$CRON_FILE"
sleep "$WAIT_SECONDS"

step 10 "Install package 'hello'"
DEBIAN_FRONTEND=noninteractive apt-get install -y hello > /dev/null
sleep "$WAIT_SECONDS"

step 11 "Remove package 'hello'"
DEBIAN_FRONTEND=noninteractive apt-get remove -y hello > /dev/null

echo "Done. Check: Endpoint security > File Integrity Monitoring > Events"
