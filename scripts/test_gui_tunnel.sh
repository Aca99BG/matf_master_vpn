#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLIENT_NS="mvpn-gui-c"
SERVER_NS="mvpn-gui-s"
CLIENT_CREATED=false
SERVER_CREATED=false
GUI_PID=""
SERVER_PID=""
LOG_DIR=$(mktemp -d)
STATE_FILE="$LOG_DIR/gui-states"
DISCONNECT_FILE="$LOG_DIR/disconnect"

cleanup() {
	set +e
	for process_id in "$GUI_PID" "$SERVER_PID"; do
		if [[ -n "$process_id" ]]; then
			kill "$process_id" 2>/dev/null
			wait "$process_id" 2>/dev/null
		fi
	done
	if [[ $CLIENT_CREATED == true ]]; then ip netns delete "$CLIENT_NS" 2>/dev/null; fi
	if [[ $SERVER_CREATED == true ]]; then ip netns delete "$SERVER_NS" 2>/dev/null; fi
	rm -rf "$LOG_DIR"
}
trap cleanup EXIT INT TERM

if [[ $EUID -ne 0 ]]; then
	printf 'Run this script as root: sudo %s\n' "$0" >&2
	exit 1
fi

for namespace in "$CLIENT_NS" "$SERVER_NS"; do
	if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
		printf 'Network namespace already exists: %s\n' "$namespace" >&2
		exit 1
	fi
done

ip netns add "$CLIENT_NS"; CLIENT_CREATED=true
ip netns add "$SERVER_NS"; SERVER_CREATED=true
ip link add gui-under-c type veth peer name gui-under-s
ip link set gui-under-c netns "$CLIENT_NS"
ip link set gui-under-s netns "$SERVER_NS"
ip -n "$CLIENT_NS" address add 192.0.2.1/30 dev gui-under-c
ip -n "$SERVER_NS" address add 192.0.2.2/30 dev gui-under-s
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set gui-under-c up
ip -n "$SERVER_NS" link set gui-under-s up

for identity in client server; do
	env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.keygen \
		--private-key "$LOG_DIR/$identity.key" \
		--public-key "$LOG_DIR/$identity.pub" >/dev/null
done

cat >"$LOG_DIR/client.json" <<EOF
{
  "tun_name": "mvpn0",
  "tun_address": "10.9.0.1/30",
  "bind": "192.0.2.1:51820",
  "peer": "192.0.2.2:51820",
  "private_key_file": "$LOG_DIR/client.key",
  "peer_public_key_file": "$LOG_DIR/server.pub",
  "role": "client",
  "ephemeral_handshake": true,
  "packets_per_key": 2,
  "json_logs": true
}
EOF

cat >"$LOG_DIR/server.json" <<EOF
{
  "tun_name": "mvpn0",
  "tun_address": "10.9.0.2/30",
  "bind": "192.0.2.2:51820",
  "peer": "192.0.2.1:51820",
  "private_key_file": "$LOG_DIR/server.key",
  "peer_public_key_file": "$LOG_DIR/client.pub",
  "role": "server",
  "ephemeral_handshake": true,
  "packets_per_key": 2,
  "json_logs": true
}
EOF

ip netns exec "$SERVER_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$LOG_DIR/server.json" >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

ip netns exec "$CLIENT_NS" env \
	QT_QPA_PLATFORM=offscreen \
	PYTHONPATH="$ROOT_DIR/src" \
	python3 "$ROOT_DIR/scripts/gui_lifecycle_harness.py" \
	--profile "$LOG_DIR/client.json" \
	--state-file "$STATE_FILE" \
	--disconnect-file "$DISCONNECT_FILE" \
	--timeout 15 >"$LOG_DIR/gui.log" 2>&1 &
GUI_PID=$!

for attempt in {1..200}; do
	if [[ -f "$STATE_FILE" ]] && grep -Fxq connected "$STATE_FILE"; then break; fi
	if ! kill -0 "$GUI_PID" 2>/dev/null; then
		cat "$LOG_DIR/gui.log" "$LOG_DIR/server.log" >&2
		exit 1
	fi
	if [[ $attempt -eq 200 ]]; then
		cat "$LOG_DIR/gui.log" "$LOG_DIR/server.log" >&2
		exit 1
	fi
	sleep 0.05
done

ip netns exec "$CLIENT_NS" ping -c 3 -W 2 10.9.0.2
touch "$DISCONNECT_FILE"

for attempt in {1..100}; do
	if ! kill -0 "$GUI_PID" 2>/dev/null; then break; fi
	if [[ $attempt -eq 100 ]]; then
		cat "$STATE_FILE" "$LOG_DIR/gui.log" >&2
		exit 1
	fi
	sleep 0.05
done
wait "$GUI_PID"
GUI_PID=""

grep -Fxq connecting "$STATE_FILE"
grep -Fxq connected "$STATE_FILE"
grep -Fxq stopping "$STATE_FILE"
grep -Fxq disconnected "$STATE_FILE"
printf '%s\n' 'PyQt VPN client connect, traffic, and disconnect: OK'