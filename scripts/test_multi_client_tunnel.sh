#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER_NS="mvpn-mserver"
FIRST_NS="mvpn-client1"
SECOND_NS="mvpn-client2"
SERVER_PID=""
FIRST_PID=""
SECOND_PID=""
SERVER_CREATED=false
FIRST_CREATED=false
SECOND_CREATED=false
LOG_DIR=$(mktemp -d)

cleanup() {
	set +e
	for process_id in "$FIRST_PID" "$SECOND_PID" "$SERVER_PID"; do
		if [[ -n "$process_id" ]]; then
			kill "$process_id" 2>/dev/null
			wait "$process_id" 2>/dev/null
		fi
	done
	if [[ $FIRST_CREATED == true ]]; then ip netns delete "$FIRST_NS" 2>/dev/null; fi
	if [[ $SECOND_CREATED == true ]]; then ip netns delete "$SECOND_NS" 2>/dev/null; fi
	if [[ $SERVER_CREATED == true ]]; then ip netns delete "$SERVER_NS" 2>/dev/null; fi
	rm -rf "$LOG_DIR"
}
trap cleanup EXIT INT TERM

if [[ $EUID -ne 0 ]]; then
	printf 'Run this script as root: sudo %s\n' "$0" >&2
	exit 1
fi

for namespace in "$SERVER_NS" "$FIRST_NS" "$SECOND_NS"; do
	if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
		printf 'Network namespace already exists: %s\n' "$namespace" >&2
		exit 1
	fi
done

ip netns add "$SERVER_NS"; SERVER_CREATED=true
ip netns add "$FIRST_NS"; FIRST_CREATED=true
ip netns add "$SECOND_NS"; SECOND_CREATED=true
ip link add mc1-under type veth peer name ms1-under
ip link add mc2-under type veth peer name ms2-under
ip link set mc1-under netns "$FIRST_NS"
ip link set ms1-under netns "$SERVER_NS"
ip link set mc2-under netns "$SECOND_NS"
ip link set ms2-under netns "$SERVER_NS"

ip -n "$FIRST_NS" address add 192.0.2.2/30 dev mc1-under
ip -n "$SERVER_NS" address add 192.0.2.1/30 dev ms1-under
ip -n "$SECOND_NS" address add 192.0.2.6/30 dev mc2-under
ip -n "$SERVER_NS" address add 192.0.2.5/30 dev ms2-under
for namespace in "$SERVER_NS" "$FIRST_NS" "$SECOND_NS"; do
	ip -n "$namespace" link set lo up
done
ip -n "$FIRST_NS" link set mc1-under up
ip -n "$SERVER_NS" link set ms1-under up
ip -n "$SECOND_NS" link set mc2-under up
ip -n "$SERVER_NS" link set ms2-under up

for identity in server first second; do
	env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.keygen \
		--private-key "$LOG_DIR/$identity.key" \
		--public-key "$LOG_DIR/$identity.pub" >/dev/null
done

cat >"$LOG_DIR/server.json" <<EOF
{
  "tun_name": "mvpn0",
  "tun_address": "10.8.0.1/24",
  "bind": "0.0.0.0:51820",
  "private_key_file": "$LOG_DIR/server.key",
  "packets_per_key": 2,
  "json_logs": true,
  "clients": [
    {"name": "first", "tunnel_address": "10.8.0.2", "public_key_file": "$LOG_DIR/first.pub"},
    {"name": "second", "tunnel_address": "10.8.0.3", "public_key_file": "$LOG_DIR/second.pub"}
  ]
}
EOF

cat >"$LOG_DIR/first.json" <<EOF
{
  "tun_name": "mvpn0",
  "tun_address": "10.8.0.2/24",
  "bind": "192.0.2.2:51820",
  "peer": "192.0.2.1:51820",
  "private_key_file": "$LOG_DIR/first.key",
  "peer_public_key_file": "$LOG_DIR/server.pub",
  "role": "client",
  "ephemeral_handshake": true,
  "packets_per_key": 2,
  "json_logs": true
}
EOF

cat >"$LOG_DIR/second.json" <<EOF
{
  "tun_name": "mvpn0",
  "tun_address": "10.8.0.3/24",
  "bind": "192.0.2.6:51820",
  "peer": "192.0.2.5:51820",
  "private_key_file": "$LOG_DIR/second.key",
  "peer_public_key_file": "$LOG_DIR/server.pub",
  "role": "client",
  "ephemeral_handshake": true,
  "packets_per_key": 2,
  "json_logs": true
}
EOF

ip netns exec "$SERVER_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.multi_server_cli \
	--config "$LOG_DIR/server.json" >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

for attempt in {1..100}; do
	if grep -Fq '"event":"multi_server_ready"' "$LOG_DIR/server.log"; then break; fi
	if [[ $attempt -eq 100 ]]; then
		cat "$LOG_DIR/server.log" >&2
		exit 1
	fi
	sleep 0.05
done

ip netns exec "$FIRST_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$LOG_DIR/first.json" >"$LOG_DIR/first.log" 2>&1 &
FIRST_PID=$!
ip netns exec "$SECOND_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$LOG_DIR/second.json" >"$LOG_DIR/second.log" 2>&1 &
SECOND_PID=$!

for attempt in {1..120}; do
	session_count=$(grep -Fc '"event":"client_session_established"' "$LOG_DIR/server.log" || true)
	if (( session_count >= 2 )) && \
		ip -n "$FIRST_NS" link show mvpn0 >/dev/null 2>&1 && \
		ip -n "$SECOND_NS" link show mvpn0 >/dev/null 2>&1 && \
		ip -n "$SERVER_NS" link show mvpn0 >/dev/null 2>&1; then
		break
	fi
	if [[ $attempt -eq 120 ]]; then
		cat "$LOG_DIR/server.log" "$LOG_DIR/first.log" "$LOG_DIR/second.log" >&2
		exit 1
	fi
	sleep 0.05
done

ip netns exec "$SERVER_NS" sysctl -q -w net.ipv6.conf.mvpn0.disable_ipv6=1
ip netns exec "$FIRST_NS" sysctl -q -w net.ipv6.conf.mvpn0.disable_ipv6=1
ip netns exec "$SECOND_NS" sysctl -q -w net.ipv6.conf.mvpn0.disable_ipv6=1

ip netns exec "$FIRST_NS" ping -c 3 -W 2 10.8.0.1
ip netns exec "$SECOND_NS" ping -c 3 -W 2 10.8.0.1
printf '%s\n' 'Multi-client VPN server: OK'