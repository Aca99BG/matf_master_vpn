#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/results/final"}
: "${SSH_HOST:?Set SSH_HOST, for example azureuser@AZURE_PUBLIC_IP}"
: "${DIRECT_TARGET:?Set DIRECT_TARGET to the Azure public or direct-path address}"
: "${PLAINTEXT_TARGET:=10.9.0.1}"
: "${PYTHON_TARGET:=10.8.0.1}"
: "${WIREGUARD_TARGET:=10.20.0.1}"
: "${OPENVPN_TARGET:=10.30.0.1}"
: "${SSH_KEY:=$HOME/.ssh/id_ed25519}"
: "${REMOTE_REPO:=/home/azureuser/matf_master_vpn}"
: "${ROUNDS:=6}"
: "${REPETITIONS_PER_BLOCK:=5}"
: "${PING_COUNT:=20}"
: "${IPERF_DURATION:=10}"
: "${UDP_BITRATE:=20M}"
: "${INTER_RUN_DELAY:=2}"
: "${SEED:=20260823}"
: "${WARMUP_DURATION:=3}"

mkdir -p "$OUTPUT_DIR/blocks" "$OUTPUT_DIR/resources" "$OUTPUT_DIR/merged"
OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
SCHEDULE="$OUTPUT_DIR/schedule.json"

if [[ ! -f "$SCHEDULE" ]]; then
	PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.experiment_cli schedule \
		--mode direct --mode plaintext --mode python --mode wireguard --mode openvpn \
		--rounds "$ROUNDS" \
		--repetitions-per-block "$REPETITIONS_PER_BLOCK" \
		--seed "$SEED" \
		--output "$SCHEDULE"
fi

target_for() {
	case "$1" in
		direct) printf '%s\n' "$DIRECT_TARGET" ;;
		plaintext) printf '%s\n' "$PLAINTEXT_TARGET" ;;
		python) printf '%s\n' "$PYTHON_TARGET" ;;
		wireguard) printf '%s\n' "$WIREGUARD_TARGET" ;;
		openvpn) printf '%s\n' "$OPENVPN_TARGET" ;;
		*) printf 'Unknown mode: %s\n' "$1" >&2; return 1 ;;
	esac
}

for command in python3 ping iperf3 ssh scp; do
	command -v "$command" >/dev/null || {
		printf 'Required command is missing: %s\n' "$command" >&2
		exit 1
	}
done
ssh -i "$SSH_KEY" "$SSH_HOST" \
	"cd '$REMOTE_REPO' && .venv/bin/python -m matf_vpn.resource_monitor --help >/dev/null"

printf '%s\n' 'Preflight and unrecorded warm-up'
for mode in direct plaintext python wireguard openvpn; do
	target=$(target_for "$mode")
	printf '  %-10s %s\n' "$mode" "$target"
	ping -n -c 2 -W 2 "$target" >/dev/null
	iperf3 --client "$target" --port 5201 --time "$WARMUP_DURATION" --json >/dev/null
done

stop_remote_monitor() {
	local stop_file=$1
	local remote_output=$2
	ssh -i "$SSH_KEY" "$SSH_HOST" "touch '$stop_file'"
	for attempt in {1..60}; do
		if ssh -i "$SSH_KEY" "$SSH_HOST" "test -s '$remote_output'"; then
			return
		fi
		sleep 0.5
	done
	printf 'Remote resource monitor did not finish: %s\n' "$remote_output" >&2
	return 1
}

while IFS=$'\t' read -r sequence round_number mode repetitions; do
	block_id=$(printf '%02d-%s' "$sequence" "$mode")
	benchmark_output="$OUTPUT_DIR/blocks/$block_id.json"
	resource_output="$OUTPUT_DIR/resources/$block_id.json"
	if [[ -s "$benchmark_output" && -s "$resource_output" ]]; then
		printf '[%s] already complete, skipping\n' "$block_id"
		continue
	fi
	target=$(target_for "$mode")
	remote_output="/tmp/matf-resource-$block_id.json"
	remote_stop="/tmp/matf-resource-$block_id.stop"
	printf '[%s] round %s, %s repetitions, target %s\n' \
		"$block_id" "$round_number" "$repetitions" "$target"

	ssh -i "$SSH_KEY" "$SSH_HOST" \
		"rm -f '$remote_output' '$remote_stop'; cd '$REMOTE_REPO'; nohup .venv/bin/python -m matf_vpn.resource_monitor --label '$block_id' --output '$remote_output' --stop-file '$remote_stop' --interval 1 >'/tmp/matf-resource-$block_id.log' 2>&1 &"
	sleep 1
	if ! PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.benchmark_cli \
		--label "$block_id" \
		--target "$target" \
		--output "$benchmark_output" \
		--repetitions "$repetitions" \
		--ping-count "$PING_COUNT" \
		--iperf-duration "$IPERF_DURATION" \
		--udp-bitrate "$UDP_BITRATE" \
		--max-attempts 3 \
		--inter-run-delay "$INTER_RUN_DELAY"; then
		stop_remote_monitor "$remote_stop" "$remote_output" || true
		exit 1
	fi
	stop_remote_monitor "$remote_stop" "$remote_output"
	scp -q -i "$SSH_KEY" "$SSH_HOST:$remote_output" "$resource_output"
done < <(
	python3 - "$SCHEDULE" <<'PY'
import json
import sys
for block in json.load(open(sys.argv[1]))["blocks"]:
    print(block["sequence"], block["round"], block["mode"], block["repetitions"], sep="\t")
PY
)

for mode in direct plaintext python wireguard openvpn; do
	benchmark_args=()
	resource_args=()
	for path in "$OUTPUT_DIR"/blocks/*-"$mode".json; do
		benchmark_args+=(--input "$path")
	done
	for path in "$OUTPUT_DIR"/resources/*-"$mode".json; do
		resource_args+=(--input "$path")
	done
	PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.experiment_cli merge \
		--label "$mode-final" \
		"${benchmark_args[@]}" \
		--output "$OUTPUT_DIR/merged/$mode.json"
	PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.resource_report \
		--label "$mode-final" \
		"${resource_args[@]}" \
		--output "$OUTPUT_DIR/merged/$mode-resources.json"
done

PYTHONPATH="$ROOT_DIR/src" python3 -m matf_vpn.benchmark_report \
	--baseline "$OUTPUT_DIR/merged/direct.json" \
	--result "$OUTPUT_DIR/merged/plaintext.json" \
	--result "$OUTPUT_DIR/merged/python.json" \
	--result "$OUTPUT_DIR/merged/wireguard.json" \
	--result "$OUTPUT_DIR/merged/openvpn.json" \
	--resource "direct-final=$OUTPUT_DIR/merged/direct-resources.json" \
	--resource "plaintext-final=$OUTPUT_DIR/merged/plaintext-resources.json" \
	--resource "python-final=$OUTPUT_DIR/merged/python-resources.json" \
	--resource "wireguard-final=$OUTPUT_DIR/merged/wireguard-resources.json" \
	--resource "openvpn-final=$OUTPUT_DIR/merged/openvpn-resources.json" \
	--output "$OUTPUT_DIR/final-comparison.csv"

printf 'Final campaign complete: %s\n' "$OUTPUT_DIR"