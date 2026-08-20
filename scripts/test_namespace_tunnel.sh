#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_NS="mvpn-client"
SERVER_NS="mvpn-server"
CLIENT_VETH="mvpn-under-c"
SERVER_VETH="mvpn-under-s"
TUN_NAME="mvpn0"
CLIENT_NS_CREATED=false
SERVER_NS_CREATED=false
CLIENT_PID=""
SERVER_PID=""
LOG_DIR=$(mktemp -d)
CLIENT_PRIVATE_KEY="$LOG_DIR/client.key"
CLIENT_PUBLIC_KEY="$LOG_DIR/client.pub"
SERVER_PRIVATE_KEY="$LOG_DIR/server.key"
SERVER_PUBLIC_KEY="$LOG_DIR/server.pub"
CLIENT_CONFIG="$LOG_DIR/client.json"
SERVER_CONFIG="$LOG_DIR/server.json"

cleanup() {
	set +e
	if [[ -n "$CLIENT_PID" ]]; then
		kill "$CLIENT_PID" 2>/dev/null
		wait "$CLIENT_PID" 2>/dev/null
	fi
	if [[ -n "$SERVER_PID" ]]; then
		kill "$SERVER_PID" 2>/dev/null
		wait "$SERVER_PID" 2>/dev/null
	fi
	if [[ $CLIENT_NS_CREATED == true ]]; then
		ip netns delete "$CLIENT_NS" 2>/dev/null
	fi
	if [[ $SERVER_NS_CREATED == true ]]; then
		ip netns delete "$SERVER_NS" 2>/dev/null
	fi
	rm -rf "$LOG_DIR"
}
trap cleanup EXIT INT TERM

if [[ $EUID -ne 0 ]]; then
	printf 'Run this script as root: sudo %s\n' "$0" >&2
	exit 1
fi

for interface_name in "$CLIENT_VETH" "$SERVER_VETH" "$TUN_NAME"; do
	if (( ${#interface_name} > 15 )); then
		printf 'Interface name exceeds Linux 15-byte limit: %s\n' "$interface_name" >&2
		exit 1
	fi
done

for namespace in "$CLIENT_NS" "$SERVER_NS"; do
	if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
		printf 'Network namespace already exists: %s\n' "$namespace" >&2
		exit 1
	fi
done

ip netns add "$CLIENT_NS"
CLIENT_NS_CREATED=true
ip netns add "$SERVER_NS"
SERVER_NS_CREATED=true
ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$SERVER_VETH" netns "$SERVER_NS"

ip -n "$CLIENT_NS" address add 192.0.2.1/30 dev "$CLIENT_VETH"
ip -n "$SERVER_NS" address add 192.0.2.2/30 dev "$SERVER_VETH"
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$SERVER_NS" link set "$SERVER_VETH" up

env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.keygen \
	--private-key "$CLIENT_PRIVATE_KEY" \
	--public-key "$CLIENT_PUBLIC_KEY" >/dev/null
env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.keygen \
	--private-key "$SERVER_PRIVATE_KEY" \
	--public-key "$SERVER_PUBLIC_KEY" >/dev/null

cat >"$CLIENT_CONFIG" <<EOF
{
  "tun_name": "$TUN_NAME",
  "tun_address": "10.0.0.1/30",
  "bind": "192.0.2.1:51820",
  "peer": "192.0.2.2:51820",
  "private_key_file": "$CLIENT_PRIVATE_KEY",
  "peer_public_key_file": "$SERVER_PUBLIC_KEY",
  "role": "client",
  "ephemeral_handshake": true,
	"handshake_timeout": 0.05,
  "packets_per_key": 2,
		"keepalive_interval": 0.1,
		"liveness_timeout": 0.4,
	"reconnect_delay": 0.2,
  "json_logs": true
}
EOF

cat >"$SERVER_CONFIG" <<EOF
{
  "tun_name": "$TUN_NAME",
  "tun_address": "10.0.0.2/30",
  "bind": "192.0.2.2:51820",
  "peer": "192.0.2.1:51820",
  "private_key_file": "$SERVER_PRIVATE_KEY",
  "peer_public_key_file": "$CLIENT_PUBLIC_KEY",
  "role": "server",
  "ephemeral_handshake": true,
	"handshake_timeout": 1.0,
  "packets_per_key": 2,
	"keepalive_interval": 0.1,
	"liveness_timeout": 0.4,
  "reconnect_delay": 0.1,
  "json_logs": true
}
EOF

start_server() {
	ip netns exec "$SERVER_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
		--config "$SERVER_CONFIG" >>"$LOG_DIR/server.log" 2>&1 &
	SERVER_PID=$!
}

ip netns exec "$CLIENT_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$CLIENT_CONFIG" >"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!

# Force the client through one failed handshake cycle to exercise reconnect.
sleep 0.25

start_server

for attempt in {1..100}; do
	if ip -n "$CLIENT_NS" link show "$TUN_NAME" >/dev/null 2>&1 && \
		ip -n "$SERVER_NS" link show "$TUN_NAME" >/dev/null 2>&1; then
		break
	fi
	if [[ $attempt -eq 100 ]]; then
		printf '%s\n' 'VPN endpoints did not become ready.' >&2
		cat "$LOG_DIR/client.log" "$LOG_DIR/server.log" >&2
		exit 1
	fi
	sleep 0.05
done

if ! grep -Fq '"event":"reconnect_scheduled"' "$LOG_DIR/client.log"; then
	printf '%s\n' 'Client did not emit the expected reconnect event.' >&2
	cat "$LOG_DIR/client.log" >&2
	exit 1
fi
for log_file in "$LOG_DIR/client.log" "$LOG_DIR/server.log"; do
	if ! grep -Fq '"event":"session_established"' "$log_file"; then
		printf 'Missing structured session event in %s\n' "$log_file" >&2
		cat "$log_file" >&2
		exit 1
	fi
done

ip netns exec "$CLIENT_NS" ping -c 3 -W 2 10.0.0.2

# Stop an established peer and require liveness detection to start a new session.
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

for attempt in {1..100}; do
	reconnect_count=$(grep -Fc '"event":"reconnect_scheduled"' "$LOG_DIR/client.log" || true)
	if (( reconnect_count >= 2 )); then
		break
	fi
	if [[ $attempt -eq 100 ]]; then
		printf '%s\n' 'Client did not detect the established peer failure.' >&2
		cat "$LOG_DIR/client.log" >&2
		exit 1
	fi
	sleep 0.05
done

start_server
for attempt in {1..120}; do
	client_sessions=$(grep -Fc '"event":"session_established"' "$LOG_DIR/client.log" || true)
	server_sessions=$(grep -Fc '"event":"session_established"' "$LOG_DIR/server.log" || true)
	if (( client_sessions >= 2 && server_sessions >= 2 )) && \
		ip -n "$CLIENT_NS" link show "$TUN_NAME" >/dev/null 2>&1 && \
		ip -n "$SERVER_NS" link show "$TUN_NAME" >/dev/null 2>&1; then
		break
	fi
	if [[ $attempt -eq 120 ]]; then
		printf '%s\n' 'VPN endpoints did not re-establish an active session.' >&2
		cat "$LOG_DIR/client.log" "$LOG_DIR/server.log" >&2
		exit 1
	fi
	sleep 0.05
done

ip netns exec "$CLIENT_NS" ping -c 3 -W 2 10.0.0.2
printf '%s\n' 'Namespace VPN tunnel, config, logging, and active reconnect: OK'