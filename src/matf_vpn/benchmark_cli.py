"""Run reproducible latency and throughput measurements."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Dict, List, Optional

from matf_vpn.benchmark import parse_iperf3_json, parse_ping_times, summarize


SCHEMA_VERSION = 1


class BenchmarkCommandError(RuntimeError):
    pass


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--namespace")
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--ping-count", type=int, default=20)
    parser.add_argument("--iperf-port", type=int, default=5201)
    parser.add_argument("--iperf-duration", type=int, default=10)
    parser.add_argument("--udp-bitrate", default="100M")
    parser.add_argument("--skip-iperf", action="store_true")
    options = parser.parse_args(arguments)
    _validate_options(options)

    prefix = ["ip", "netns", "exec", options.namespace] if options.namespace else []
    if not options.skip_iperf and shutil.which("iperf3") is None:
        parser.error("iperf3 is required unless --skip-iperf is used")

    result = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": options.label,
        "parameters": {
            "target": options.target,
            "namespace": options.namespace,
            "repetitions": options.repetitions,
            "ping_count": options.ping_count,
            "iperf_port": options.iperf_port,
            "iperf_duration": options.iperf_duration,
            "udp_bitrate": options.udp_bitrate,
            "skip_iperf": options.skip_iperf,
        },
        "environment": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "latency": _run_latency(prefix, options),
    }
    if not options.skip_iperf:
        result["tcp"] = _run_iperf(prefix, options, "tcp")
        result["udp"] = _run_iperf(prefix, options, "udp")

    options.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = options.output.with_suffix(options.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(options.output)
    print(options.output)
    return 0


def _run_latency(prefix: List[str], options: argparse.Namespace) -> Dict[str, object]:
    samples = []
    runs = []
    for repetition in range(options.repetitions):
        command = prefix + [
            "ping",
            "-n",
            "-c",
            str(options.ping_count),
            "-W",
            "2",
            options.target,
        ]
        output = _run(command)
        run_samples = parse_ping_times(output)
        samples.extend(run_samples)
        runs.append({"repetition": repetition + 1, "rtt_ms": run_samples})
    return {
        "unit": "ms",
        "raw_runs": runs,
        "summary": summarize(samples).to_dict(),
    }


def _run_iperf(
    prefix: List[str],
    options: argparse.Namespace,
    protocol: str,
) -> Dict[str, object]:
    runs = []
    throughput_samples = []
    for repetition in range(options.repetitions):
        command = prefix + [
            "iperf3",
            "--client",
            options.target,
            "--port",
            str(options.iperf_port),
            "--time",
            str(options.iperf_duration),
            "--json",
        ]
        if protocol == "udp":
            command.extend(["--udp", "--bitrate", options.udp_bitrate])
        metrics = parse_iperf3_json(_run(command), protocol)
        runs.append({"repetition": repetition + 1, **metrics})
        throughput_samples.append(metrics["bits_per_second"])
    return {
        "raw_runs": runs,
        "throughput_summary_bps": summarize(throughput_samples).to_dict(),
    }


def _run(command: List[str]) -> str:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rendered_command = " ".join(command)
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise BenchmarkCommandError(
            f"command failed with exit {completed.returncode}: "
            f"{rendered_command}\n{detail}"
        )
    return completed.stdout


def _validate_options(options: argparse.Namespace) -> None:
    if options.repetitions <= 0 or options.ping_count <= 0:
        raise SystemExit("repetitions and ping count must be positive")
    if options.iperf_duration <= 0:
        raise SystemExit("iperf duration must be positive")
    if not 1 <= options.iperf_port <= 65_535:
        raise SystemExit("iperf port must be between 1 and 65535")


if __name__ == "__main__":
    raise SystemExit(main())
