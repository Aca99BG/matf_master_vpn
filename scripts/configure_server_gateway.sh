#!/usr/bin/env bash
set -euo pipefail

TUNNEL_SUBNET=${1:-10.8.0.0/24}
OUTBOUND_INTERFACE=${2:-$(ip route show default | awk 'NR==1 {print $5}')}

if [[ $EUID -ne 0 ]]; then
	printf 'Run as root: sudo %s [TUNNEL_SUBNET] [OUTBOUND_INTERFACE]\n' "$0" >&2
	exit 1
fi
if [[ -z "$OUTBOUND_INTERFACE" ]]; then
	printf '%s\n' 'Could not determine the outbound interface.' >&2
	exit 1
fi

cat >/etc/sysctl.d/99-matf-vpn.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

iptables -C FORWARD -i mvpn0 -o "$OUTBOUND_INTERFACE" -j ACCEPT 2>/dev/null || \
	iptables -A FORWARD -i mvpn0 -o "$OUTBOUND_INTERFACE" -j ACCEPT
iptables -C FORWARD -i "$OUTBOUND_INTERFACE" -o mvpn0 \
	-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
	iptables -A FORWARD -i "$OUTBOUND_INTERFACE" -o mvpn0 \
		-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$TUNNEL_SUBNET" -o "$OUTBOUND_INTERFACE" \
	-j MASQUERADE 2>/dev/null || \
	iptables -t nat -A POSTROUTING -s "$TUNNEL_SUBNET" -o "$OUTBOUND_INTERFACE" \
		-j MASQUERADE

printf 'IPv4 forwarding and NAT configured for %s through %s\n' \
	"$TUNNEL_SUBNET" "$OUTBOUND_INTERFACE"