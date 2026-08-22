#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/results/local"}
REPETITIONS=${REPETITIONS:-5}
PING_COUNT=${PING_COUNT:-10}
IPERF_DURATION=${IPERF_DURATION:-3}
CLIENT_NS="mvpn-bench-c"
SERVER_NS="mvpn-bench-s"
CLIENT_CREATED=false
SERVER_CREATED=false
CLIENT_PID=""
SERVER_PID=""
IPERF_PID=""
WORK_DIR=$(mktemp -d)
CURRENT_PHASE="setup"
RESULT_UID=${SUDO_UID:-$(id -u)}
RESULT_GID=${SUDO_GID:-$(id -g)}

cleanup() {
	set +e
	for process_id in "$CLIENT_PID" "$SERVER_PID" "$IPERF_PID"; do
		if [[ -n "$process_id" ]]; then
			kill "$process_id" 2>/dev/null || true
			wait "$process_id" 2>/dev/null || true
		fi
	done
	if [[ $CLIENT_CREATED == true ]]; then ip netns delete "$CLIENT_NS" 2>/dev/null; fi
	if [[ $SERVER_CREATED == true ]]; then ip netns delete "$SERVER_NS" 2>/dev/null; fi
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

on_error() {
	local exit_code=$?
	mkdir -p "$OUTPUT_DIR" 2>/dev/null || true
	for log_file in "$WORK_DIR"/*.log; do
		if [[ -f "$log_file" ]]; then
			cp "$log_file" "$OUTPUT_DIR/failed-$(basename "$log_file")" 2>/dev/null || true
		fi
	done
	chown -R "$RESULT_UID:$RESULT_GID" "$OUTPUT_DIR" 2>/dev/null || true
	printf 'Benchmark failed during phase: %s (exit %d)\n' "$CURRENT_PHASE" "$exit_code" >&2
	printf 'Diagnostic logs: %s/failed-*.log\n' "$OUTPUT_DIR" >&2
	exit "$exit_code"
}
trap on_error ERR

if [[ $EUID -ne 0 ]]; then
	printf 'Run this script as root: sudo %s [OUTPUT_DIR]\n' "$0" >&2
	exit 1
fi
if ! command -v iperf3 >/dev/null; then
	printf '%s\n' 'iperf3 is required: sudo apt-get install iperf3' >&2
	exit 1
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
rm -f "$OUTPUT_DIR"/failed-*.log

ip netns add "$CLIENT_NS"; CLIENT_CREATED=true
ip netns add "$SERVER_NS"; SERVER_CREATED=true
ip link add bench-under-c type veth peer name bench-under-s
ip link set bench-under-c netns "$CLIENT_NS"
ip link set bench-under-s netns "$SERVER_NS"
ip -n "$CLIENT_NS" address add 192.0.2.1/30 dev bench-under-c
ip -n "$SERVER_NS" address add 192.0.2.2/30 dev bench-under-s
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set bench-under-c up
ip -n "$SERVER_NS" link set bench-under-s up

ip netns exec "$SERVER_NS" iperf3 --server >"$WORK_DIR/iperf.log" 2>&1 &
IPERF_PID=$!

run_benchmark() {
	local label=$1
	local target=$2
	ip netns exec "$CLIENT_NS" env PYTHONPATH="$ROOT_DIR/src" \
		python3 -m matf_vpn.benchmark_cli \
		--label "$label" \
		--target "$target" \
		--output "$OUTPUT_DIR/$label.json" \
		--repetitions "$REPETITIONS" \
		--ping-count "$PING_COUNT" \
		--iperf-duration "$IPERF_DURATION"
}

stop_tunnel() {
	for process_id in "$CLIENT_PID" "$SERVER_PID"; do
		if [[ -n "$process_id" ]]; then
			kill "$process_id" 2>/dev/null || true
			wait "$process_id" 2>/dev/null || true
		fi
	done
	CLIENT_PID=""
	SERVER_PID=""
}

wait_for_tunnel() {
	for attempt in {1..120}; do
		if ip -n "$CLIENT_NS" link show mvpn0 >/dev/null 2>&1 && \
			ip -n "$SERVER_NS" link show mvpn0 >/dev/null 2>&1; then
			return
		fi
		sleep 0.05
	done
	cat "$WORK_DIR/client.log" "$WORK_DIR/server.log" >&2
	return 1
}

CURRENT_PHASE="direct baseline"
printf '%s\n' '[1/4] Measuring direct baseline'
run_benchmark direct 192.0.2.2

cat >"$WORK_DIR/plain-client.json" <<EOF
{"tun_address":"10.10.0.1/30","bind":"192.0.2.1:51820","peer":"192.0.2.2:51820","session_id":1}
EOF
cat >"$WORK_DIR/plain-server.json" <<EOF
{"tun_address":"10.10.0.2/30","bind":"192.0.2.2:51820","peer":"192.0.2.1:51820","session_id":1}
EOF
ip netns exec "$SERVER_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$WORK_DIR/plain-server.json" >"$WORK_DIR/server.log" 2>&1 & SERVER_PID=$!
ip netns exec "$CLIENT_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$WORK_DIR/plain-client.json" >"$WORK_DIR/client.log" 2>&1 & CLIENT_PID=$!
wait_for_tunnel
CURRENT_PHASE="plaintext Python VPN"
printf '%s\n' '[2/4] Measuring plaintext Python VPN'
run_benchmark plaintext-python 10.10.0.2
stop_tunnel

for identity in client server; do
	env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.keygen \
		--private-key "$WORK_DIR/$identity.key" \
		--public-key "$WORK_DIR/$identity.pub" >/dev/null
done
cat >"$WORK_DIR/encrypted-client.json" <<EOF
{"tun_address":"10.10.0.1/30","bind":"192.0.2.1:51820","peer":"192.0.2.2:51820","private_key_file":"$WORK_DIR/client.key","peer_public_key_file":"$WORK_DIR/server.pub","role":"client","ephemeral_handshake":true,"packets_per_key":100000}
EOF
cat >"$WORK_DIR/encrypted-server.json" <<EOF
{"tun_address":"10.10.0.2/30","bind":"192.0.2.2:51820","peer":"192.0.2.1:51820","private_key_file":"$WORK_DIR/server.key","peer_public_key_file":"$WORK_DIR/client.pub","role":"server","ephemeral_handshake":true,"packets_per_key":100000}
EOF
ip netns exec "$SERVER_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$WORK_DIR/encrypted-server.json" >"$WORK_DIR/server.log" 2>&1 & SERVER_PID=$!
ip netns exec "$CLIENT_NS" env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn \
	--config "$WORK_DIR/encrypted-client.json" >"$WORK_DIR/client.log" 2>&1 & CLIENT_PID=$!
wait_for_tunnel
CURRENT_PHASE="encrypted Python VPN"
printf '%s\n' '[3/4] Measuring encrypted Python VPN'
run_benchmark encrypted-python 10.10.0.2

CURRENT_PHASE="comparison report"
printf '%s\n' '[4/4] Generating comparison report'
env PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.benchmark_report \
	--baseline "$OUTPUT_DIR/direct.json" \
	--result "$OUTPUT_DIR/plaintext-python.json" \
	--result "$OUTPUT_DIR/encrypted-python.json" \
	--output "$OUTPUT_DIR/comparison.csv"
chown -R "$RESULT_UID:$RESULT_GID" "$OUTPUT_DIR"
printf 'Benchmark results: %s\n' "$OUTPUT_DIR"
