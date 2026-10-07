#!/bin/bash
# Forwarding, NAT and MSS clamping for WireGuard Portal VPN clients
# Goes to: /usr/local/sbin/wg-portal-nat.sh on wazuh-server
set -e
VPN_NET="10.11.12.0/24"; WG_IF="wg0"
WAN_IF="$(ip -4 route show default | awk '{print $5; exit}')"
CHAIN=DOCKER-USER; iptables -nL DOCKER-USER >/dev/null 2>&1 || CHAIN=FORWARD
rule() { local t=$1 c=$2; shift 2
  iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -I "$c" 1 "$@"; }
rule filter "$CHAIN" -i "$WG_IF" -o "$WAN_IF" -j ACCEPT
rule filter "$CHAIN" -i "$WAN_IF" -o "$WG_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
rule nat POSTROUTING -s "$VPN_NET" -o "$WAN_IF" -j MASQUERADE
rule mangle FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
rule mangle FORWARD -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
echo "WG NAT applied (WAN=$WAN_IF, chain=$CHAIN)"
