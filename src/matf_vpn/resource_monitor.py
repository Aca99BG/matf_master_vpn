"""Collect Linux CPU and memory samples during a benchmark block."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Dict, List, Optional, Tuple

from matf_vpn.benchmark import summarize


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--process-match")
    options = parser.parse_args(arguments)
    if options.interval <= 0:
        parser.error("interval must be positive")

    started_at = datetime.now(timezone.utc).isoformat()
    samples = collect_samples(
        options.stop_file,
        options.interval,
        options.process_match,
    )
    if not samples:
        parser.error("monitor stopped before collecting a sample")
    result = {
        "schema_version": 1,
        "label": options.label,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "interval_seconds": options.interval,
        "process_match": options.process_match,
        "raw_samples": samples,
        "summary": {
            "system_cpu_percent": summarize(
                sample["system_cpu_percent"] for sample in samples
            ).to_dict(),
            "memory_used_mib": summarize(
                sample["memory_used_mib"] for sample in samples
            ).to_dict(),
            "memory_used_percent": summarize(
                sample["memory_used_percent"] for sample in samples
            ).to_dict(),
        },
    }
    process_rss = [
        sample["process_rss_mib"]
        for sample in samples
        if sample["process_rss_mib"] is not None
    ]
    if process_rss:
        result["summary"]["process_rss_mib"] = summarize(process_rss).to_dict()

    options.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = options.output.with_suffix(options.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(options.output)
    print(options.output)
    return 0


def collect_samples(
    stop_file: Path,
    interval: float,
    process_match: Optional[str],
) -> List[Dict[str, object]]:
    samples = []
    previous_cpu = read_cpu_times()
    while not stop_file.exists():
        time.sleep(interval)
        current_cpu = read_cpu_times()
        memory = read_memory()
        samples.append(
            {
                "elapsed_seconds": len(samples) * interval + interval,
                "system_cpu_percent": cpu_percent(previous_cpu, current_cpu),
                "memory_used_mib": memory["used_kib"] / 1024,
                "memory_used_percent": memory["used_kib"] / memory["total_kib"] * 100,
                "process_rss_mib": process_rss_mib(process_match)
                if process_match
                else None,
            }
        )
        previous_cpu = current_cpu
    return samples


def read_cpu_times(path: Path = Path("/proc/stat")) -> Tuple[int, int]:
    first_line = path.read_text(encoding="ascii").splitlines()[0]
    fields = [int(value) for value in first_line.split()[1:]]
    total = sum(fields)
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return total, idle


def cpu_percent(previous: Tuple[int, int], current: Tuple[int, int]) -> float:
    total_delta = current[0] - previous[0]
    idle_delta = current[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    return max(0.0, min(100.0, (total_delta - idle_delta) / total_delta * 100))


def read_memory(path: Path = Path("/proc/meminfo")) -> Dict[str, int]:
    fields = {}
    for line in path.read_text(encoding="ascii").splitlines():
        name, value = line.split(":", 1)
        fields[name] = int(value.strip().split()[0])
    total = fields["MemTotal"]
    available = fields["MemAvailable"]
    return {"total_kib": total, "used_kib": total - available}


def process_rss_mib(pattern: str, proc_root: Path = Path("/proc")) -> Optional[float]:
    total_kib = 0
    matched = False
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8",
                errors="replace",
            )
            if pattern not in command:
                continue
            status = (entry / "status").read_text(encoding="ascii")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                total_kib += int(line.split()[1])
                matched = True
                break
    return total_kib / 1024 if matched else None


if __name__ == "__main__":
    raise SystemExit(main())