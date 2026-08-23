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
    "latency_loss_percent",
    "latency_overhead_percent",
    "tcp_mean_mbps",
    "tcp_change_percent",
    "udp_mean_mbps",
    "udp_effective_mean_mbps",
    "udp_change_percent",
    "udp_mean_jitter_ms",
    "udp_mean_loss_percent",
    "server_cpu_mean_percent",
    "server_cpu_p95_percent",
    "server_memory_mean_mib",
    "server_memory_p95_mib",
]


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", default=[])
    parser.add_argument(
        "--resource",
        action="append",
        default=[],
        metavar="LABEL=PATH",
    )
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)

    baseline = _load(options.baseline)
    documents = [baseline] + [_load(path) for path in options.result]
    resources = _load_resources(options.resource)
    baseline_metrics = _metrics(baseline, resources.get(baseline["label"]))
    rows = []
    for document in documents:
        metrics = _metrics(document, resources.get(document["label"]))
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


def _metrics(
    document: Dict[str, object],
    resource: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    latency = document["latency"]["summary"]
    tcp_runs = document.get("tcp", {}).get("raw_runs", [])
    udp_runs = document.get("udp", {}).get("raw_runs", [])
    metrics = {
        "label": document["label"],
        "latency_median_ms": latency["median"],
        "latency_p95_ms": latency["p95"],
        "latency_loss_percent": document["latency"].get("lost_percent", ""),
        "latency_overhead_percent": 0.0,
        "tcp_mean_mbps": _mean_metric(tcp_runs, "bits_per_second", 1_000_000),
        "tcp_change_percent": "",
        "udp_mean_mbps": _mean_metric(udp_runs, "bits_per_second", 1_000_000),
        "udp_effective_mean_mbps": _mean_udp_effective_mbps(udp_runs),
        "udp_change_percent": "",
        "udp_mean_jitter_ms": _mean_metric(udp_runs, "jitter_ms"),
        "udp_mean_loss_percent": _mean_metric(udp_runs, "lost_percent"),
        "server_cpu_mean_percent": "",
        "server_cpu_p95_percent": "",
        "server_memory_mean_mib": "",
        "server_memory_p95_mib": "",
    }
    if resource is not None:
        summary = resource["summary"]
        metrics.update(
            {
                "server_cpu_mean_percent": summary["system_cpu_percent"]["mean"],
                "server_cpu_p95_percent": summary["system_cpu_percent"]["p95"],
                "server_memory_mean_mib": summary["memory_used_mib"]["mean"],
                "server_memory_p95_mib": summary["memory_used_mib"]["p95"],
            }
        )
    return metrics


def _mean_metric(runs, field: str, divisor: float = 1.0):
    values = [float(run[field]) / divisor for run in runs if field in run]
    return statistics.fmean(values) if values else ""


def _mean_udp_effective_mbps(runs):
    values = [
        float(run["bits_per_second"])
        / 1_000_000
        * (1 - float(run.get("lost_percent", 0.0)) / 100)
        for run in runs
        if "bits_per_second" in run
    ]
    return statistics.fmean(values) if values else ""


def _change(baseline: float, value: float) -> float:
    if baseline == 0:
        raise ValueError("baseline metric must not be zero")
    return (value - baseline) / baseline * 100


def _change_optional(baseline, value):
    if baseline == "" or value == "":
        return ""
    return _change(float(baseline), float(value))


def _load_resources(entries: List[str]) -> Dict[str, Dict[str, object]]:
    resources = {}
    for entry in entries:
        if "=" not in entry:
            raise ValueError("resource must use LABEL=PATH format")
        label, raw_path = entry.split("=", 1)
        if label in resources:
            raise ValueError(f"duplicate resource label: {label}")
        try:
            document = json.loads(Path(raw_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"cannot load resource result {raw_path}: {error}") from error
        resources[label] = document
    return resources


if __name__ == "__main__":
    raise SystemExit(main())
