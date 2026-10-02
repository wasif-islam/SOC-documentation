#!/usr/bin/env bash
# =============================================================================
# ufw firewall rules for: ubuntu-endpoint
# Run on:                 ubuntu-endpoint, as a user with sudo
# Usage:                  sudo bash ufw-ubuntu-endpoint.sh
#
# What it allows (everything else inbound is blocked):
#   22/tcp   SSH   from anywhere (the cloud firewall limits it to your IP)
#
# The Wazuh agent needs NO inbound port. It opens the connection itself
# (outbound) to wazuh-server on 1514/tcp and 1515/tcp, and outbound traffic
# is allowed by default.
# =============================================================================
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: run with sudo:  sudo bash $0" >&2
  exit 1
fi

ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp comment 'SSH'

ufw --force enable
ufw status numbered
