#!/bin/bash
# =============================================================================
# File:    /var/ossec/active-response/bin/yara.sh
# Machine: ubuntu-endpoint
# Purpose: Wazuh active response script. The Wazuh server runs it on the agent
#          when a file is added or changed in /opt/yara-lab. It scans that file
#          with YARA and writes every match to /var/ossec/logs/active-responses.log.
#          The agent sends that log back to the Wazuh server.
# Based on the Wazuh YARA proof-of-concept script (GPLv2, Copyright Wazuh Inc.)
# =============================================================================

# Wazuh sends the alert and the extra arguments as one JSON line
read -r INPUT_JSON
YARA_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[1]')
YARA_RULES=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[3]')
FILENAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path')

# Path relative to /var/ossec (active response scripts run from there)
LOG_FILE="logs/active-responses.log"

# Wait until the file stops growing (it may still be downloading)
size=0
actual_size=$(stat -c %s "$FILENAME" 2>/dev/null || echo 0)
while [ "$size" -ne "$actual_size" ]; do
    sleep 1
    size=$actual_size
    actual_size=$(stat -c %s "$FILENAME" 2>/dev/null || echo 0)
done

if [[ -z $YARA_PATH || $YARA_PATH == "null" || -z $YARA_RULES || $YARA_RULES == "null" ]]; then
    echo "wazuh-yara: ERROR - Yara path and rules parameters are mandatory." >> "$LOG_FILE"
    exit 1
fi

# Scan the file. YARA prints one line per match: "<rule name> <file>"
yara_output="$("$YARA_PATH"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ -n $yara_output ]]; then
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "$LOG_FILE"
    done <<< "$yara_output"
fi

exit 0
