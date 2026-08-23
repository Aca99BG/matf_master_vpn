"""Planning and aggregation helpers for final benchmark campaigns."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import random
from pathlib import Path
from typing import Dict, List, Sequence

from matf_vpn.benchmark import summarize


@dataclass(frozen=True)
class ScheduledBlock:
    sequence: int
    round_number: int
    mode: str
    repetitions: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "sequence": self.sequence,
            "round": self.round_number,
            "mode": self.mode,
            "repetitions": self.repetitions,
        }


def create_balanced_schedule(
    modes: Sequence[str],
    rounds: int,
    repetitions_per_block: int,
    seed: int,
) -> List[ScheduledBlock]:
    normalized_modes = list(modes)
    if len(normalized_modes) < 2:
        raise ValueError("at least two benchmark modes are required")
    if len(set(normalized_modes)) != len(normalized_modes):
        raise ValueError("benchmark mode names must be unique")
    if any(not mode.strip() for mode in normalized_modes):
        raise ValueError("benchmark mode names must not be empty")
    if rounds <= 0 or repetitions_per_block <= 0:
        raise ValueError("rounds and repetitions per block must be positive")

    generator = random.Random(seed)
    schedule = []
    sequence = 1
    previous_last = None
    for round_number in range(1, rounds + 1):
        order = normalized_modes.copy()
        generator.shuffle(order)
        if previous_last is not None and order[0] == previous_last:
            swap_index = next(
                index for index, mode in enumerate(order[1:], start=1) if mode != previous_last
            )
            order[0], order[swap_index] = order[swap_index], order[0]
        for mode in order:
            schedule.append(
                ScheduledBlock(
                    sequence,
                    round_number,
                    mode,
                    repetitions_per_block,
                )
            )
            sequence += 1
        previous_last = order[-1]
    return schedule


COMPARABILITY_FIELDS = (
    "target",
    "ping_count",
    "iperf_port",
    "iperf_duration",
    "udp_bitrate",
    "skip_iperf",
)


def merge_benchmark_blocks(
    paths: Sequence[Path],
    label: str,
) -> Dict[str, object]:
    if not paths:
        raise ValueError("at least one benchmark block is required")
    documents = [_load_result(path) for path in paths]
    reference_parameters = documents[0]["parameters"]
    for document in documents[1:]:
        for field in COMPARABILITY_FIELDS:
            if document["parameters"].get(field) != reference_parameters.get(field):
                raise ValueError(f"benchmark blocks differ in parameter: {field}")

    latency_runs = []
    latency_samples = []
    for block_number, document in enumerate(documents, start=1):
        for run in document["latency"]["raw_runs"]:
            samples = [float(value) for value in run["rtt_ms"]]
            latency_runs.append(
                {
                    "repetition": len(latency_runs) + 1,
                    "block": block_number,
                    "rtt_ms": samples,
                }
            )
            latency_samples.extend(samples)

    merged = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "parameters": {
            **reference_parameters,
            "repetitions": len(latency_runs),
            "source_blocks": len(documents),
        },
        "environment": documents[0]["environment"],
        "source_files": [str(path) for path in paths],
        "latency": {
            "unit": "ms",
            "raw_runs": latency_runs,
            "expected_samples": len(latency_runs) * int(reference_parameters["ping_count"]),
            "received_samples": len(latency_samples),
            "lost_percent": (
                (len(latency_runs) * int(reference_parameters["ping_count"]) - len(latency_samples))
                / (len(latency_runs) * int(reference_parameters["ping_count"]))
                * 100
            ),
            "summary": summarize(latency_samples).to_dict(),
        },
    }
    for protocol in ("tcp", "udp"):
        if protocol in documents[0]:
            merged[protocol] = _merge_throughput(documents, protocol)
    return merged


def _merge_throughput(documents: Sequence[Dict[str, object]], protocol: str):
    runs = []
    failures = []
    throughput = []
    for block_number, document in enumerate(documents, start=1):
        section = document[protocol]
        for run in section["raw_runs"]:
            merged_run = {
                **run,
                "repetition": len(runs) + 1,
                "block": block_number,
            }
            runs.append(merged_run)
            throughput.append(float(run["bits_per_second"]))
        for failure in section.get("failed_attempts", []):
            failures.append({**failure, "block": block_number})
    return {
        "raw_runs": runs,
        "failed_attempts": failures,
        "throughput_summary_bps": summarize(throughput).to_dict(),
    }


def _load_result(path: Path) -> Dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load benchmark block {path}: {error}") from error
    if document.get("schema_version") != 1:
        raise ValueError(f"unsupported benchmark schema in {path}")
    return document
