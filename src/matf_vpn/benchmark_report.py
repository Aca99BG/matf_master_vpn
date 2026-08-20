"""Generate a comparison CSV from benchmark result documents."""

import argparse
import csv
import json
from pathlib import Path
import statistics
from typing import Dict, List, Optional


REPORT_FIELDS = [
    "label",
    "latency_median_ms",
    "latency_p95_ms",
    "latency_overhead_percent",
    "tcp_mean_mbps",
    "tcp_change_percent",
    "udp_mean_mbps",
    "udp_change_percent",
    "udp_mean_jitter_ms",
    "udp_mean_loss_percent",
]


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)

    baseline = _load(options.baseline)
    documents = [baseline] + [_load(path) for path in options.result]
    baseline_metrics = _metrics(baseline)
    rows = []
    for document in documents:
        metrics = _metrics(document)
        metrics["latency_overhead_percent"] = _change(
            baseline_metrics["latency_median_ms"],
            metrics["latency_median_ms"],
        )
        metrics["tcp_change_percent"] = _change_optional(
            baseline_metrics["tcp_mean_mbps"],
            metrics["tcp_mean_mbps"],
        )
        metrics["udp_change_percent"] = _change_optional(
            baseline_metrics["udp_mean_mbps"],
            metrics["udp_mean_mbps"],
        )
        rows.append(metrics)

    options.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = options.output.with_suffix(options.output.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(options.output)
    print(options.output)
    return 0


def _load(path: Path) -> Dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load benchmark result {path}: {error}") from error
    if document.get("schema_version") != 1:
        raise ValueError(f"unsupported benchmark schema in {path}")
    return document


def _metrics(document: Dict[str, object]) -> Dict[str, object]:
    latency = document["latency"]["summary"]
    tcp_runs = document.get("tcp", {}).get("raw_runs", [])
    udp_runs = document.get("udp", {}).get("raw_runs", [])
    return {
        "label": document["label"],
        "latency_median_ms": latency["median"],
        "latency_p95_ms": latency["p95"],
        "latency_overhead_percent": 0.0,
        "tcp_mean_mbps": _mean_metric(tcp_runs, "bits_per_second", 1_000_000),
        "tcp_change_percent": "",
        "udp_mean_mbps": _mean_metric(udp_runs, "bits_per_second", 1_000_000),
        "udp_change_percent": "",
        "udp_mean_jitter_ms": _mean_metric(udp_runs, "jitter_ms"),
        "udp_mean_loss_percent": _mean_metric(udp_runs, "lost_percent"),
    }


def _mean_metric(runs, field: str, divisor: float = 1.0):
    values = [float(run[field]) / divisor for run in runs if field in run]
    return statistics.fmean(values) if values else ""


def _change(baseline: float, value: float) -> float:
    if baseline == 0:
        raise ValueError("baseline metric must not be zero")
    return (value - baseline) / baseline * 100


def _change_optional(baseline, value):
    if baseline == "" or value == "":
        return ""
    return _change(float(baseline), float(value))


if __name__ == "__main__":
    raise SystemExit(main())
