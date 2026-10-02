#!/usr/bin/env bash
# =============================================================================
# ufw firewall rules for: wazuh-server
# Run on:                 wazuh-server, as a user with sudo
# Usage:                  edit the three variables below, then:  sudo bash ufw-wazuh-server.sh
#
# What it allows (everything else inbound is blocked):
#   22/tcp   SSH                 from anywhere (the cloud firewall limits it to your IP;
#                                kept open here so you are not locked out if your
#                                home IP changes)
#   443/tcp  Wazuh dashboard     only from YOUR_PUBLIC_IP
#   1514/tcp Agent events        only from ENDPOINT_PRIVATE_IP and WINDOWS_PRIVATE_IP
#   1515/tcp Agent enrollment    only from ENDPOINT_PRIVATE_IP and WINDOWS_PRIVATE_IP
#
# Ports 9200 (indexer) and 55000 (server API) are NOT opened. They are only
# used inside this VM (all-in-one deployment).
# =============================================================================
set -euo pipefail

# ---- CHANGE THESE THREE LINES ------------------------------------------------
YOUR_PUBLIC_IP="<YOUR_PUBLIC_IP>"            # e.g. 203.0.113.25  (curl -4 ifconfig.me on YOUR computer)
ENDPOINT_PRIVATE_IP="<ENDPOINT_PRIVATE_IP>"  # e.g. 10.0.1.20     (private IP of ubuntu-endpoint)
WINDOWS_PRIVATE_IP="<WINDOWS_PRIVATE_IP>"    # e.g. 10.0.1.30     (private IP of windows-endpoint)
# ------------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo:  sudo bash $0" >&2
  exit 1
fi

if [[ "$YOUR_PUBLIC_IP" == *"<"* || "$ENDPOINT_PRIVATE_IP" == *"<"* || "$WINDOWS_PRIVATE_IP" == *"<"* ]]; then
  echo "ERROR: edit the three variables at the top of this script first." >&2
  exit 1
fi

ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp comment 'SSH'
ufw allow from "$YOUR_PUBLIC_IP" to any port 443 proto tcp comment 'Wazuh dashboard'
for ip in "$ENDPOINT_PRIVATE_IP" "$WINDOWS_PRIVATE_IP"; do
  ufw allow from "$ip" to any port 1514 proto tcp comment 'Wazuh agent events'
  ufw allow from "$ip" to any port 1515 proto tcp comment 'Wazuh agent enrollment'
done

ufw --force enable
ufw status numbered
