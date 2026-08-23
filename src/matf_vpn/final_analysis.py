"""Generate statistical tests, figures, and a Markdown final evaluation report."""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import statistics
from typing import Callable, Dict, List, Optional, Sequence, Tuple


MODES = ("direct", "plaintext", "python", "wireguard", "openvpn")
DISPLAY_NAMES = {
    "direct": "Direct",
    "plaintext": "Plaintext Python",
    "python": "Encrypted Python",
    "wireguard": "WireGuard",
    "openvpn": "OpenVPN",
}


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    unit: str
    extractor: Callable[[Dict[str, object]], List[float]]


def main(arguments: Optional[List[str]] = None) -> int:
    _analysis_dependencies()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    options = parser.parse_args(arguments)

    benchmarks = {
        mode: _load(options.input_dir / f"{mode}.json") for mode in MODES
    }
    resources = {
        mode: _load(options.input_dir / f"{mode}-resources.json") for mode in MODES
    }
    metrics = benchmark_metrics() + resource_metrics(resources)
    analysis = {
        "schema_version": 1,
        "modes": list(MODES),
        "metrics": {},
    }

    options.output_dir.mkdir(parents=True, exist_ok=True)
    for metric in metrics:
        values = {
            mode: metric.extractor(benchmarks[mode])
            if not metric.key.startswith("server_")
            else resource_values(resources[mode], metric.key)
            for mode in MODES
        }
        analysis["metrics"][metric.key] = analyze_metric(values)
        plot_metric(metric, values, options.output_dir / f"{metric.key}.png")

    (options.output_dir / "statistics.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (options.output_dir / "analysis.md").write_text(
        render_markdown(benchmarks, analysis),
        encoding="utf-8",
    )
    print(options.output_dir / "analysis.md")
    return 0


def benchmark_metrics() -> List[Metric]:
    return [
        Metric(
            "rtt_run_median_ms",
            "RTT median po ponavljanju",
            "ms",
            lambda document: [
                statistics.median(run["rtt_ms"])
                for run in document["latency"]["raw_runs"]
            ],
        ),
        Metric(
            "tcp_mbps",
            "TCP throughput",
            "Mbps",
            lambda document: [
                run["bits_per_second"] / 1_000_000
                for run in document["tcp"]["raw_runs"]
            ],
        ),
        Metric(
            "udp_effective_mbps",
            "UDP efektivni goodput",
            "Mbps",
            lambda document: [
                run["bits_per_second"]
                / 1_000_000
                * (1 - run.get("lost_percent", 0.0) / 100)
                for run in document["udp"]["raw_runs"]
            ],
        ),
        Metric(
            "udp_jitter_ms",
            "UDP jitter",
            "ms",
            lambda document: [run["jitter_ms"] for run in document["udp"]["raw_runs"]],
        ),
        Metric(
            "udp_loss_percent",
            "UDP gubitak",
            "%",
            lambda document: [
                run["lost_percent"] for run in document["udp"]["raw_runs"]
            ],
        ),
    ]


def resource_metrics(resources: Dict[str, Dict[str, object]]) -> List[Metric]:
    return [
        Metric("server_cpu_percent", "Server CPU po bloku", "%", lambda _: []),
        Metric("server_memory_mib", "Server RAM po bloku", "MiB", lambda _: []),
    ]


def resource_values(document: Dict[str, object], key: str) -> List[float]:
    field = "system_cpu_percent" if key == "server_cpu_percent" else "memory_used_mib"
    blocks: Dict[int, List[float]] = {}
    for sample in document["raw_samples"]:
        blocks.setdefault(int(sample["block"]), []).append(float(sample[field]))
    return [statistics.fmean(blocks[block]) for block in sorted(blocks)]


def analyze_metric(values: Dict[str, List[float]]) -> Dict[str, object]:
    from scipy import stats

    groups = [values[mode] for mode in MODES]
    kruskal = stats.kruskal(*groups)
    result = {
        "sample_sizes": {mode: len(values[mode]) for mode in MODES},
        "descriptive": {
            mode: describe(values[mode]) for mode in MODES
        },
        "kruskal_wallis": {
            "statistic": float(kruskal.statistic),
            "p_value": float(kruskal.pvalue),
        },
        "pairwise_mann_whitney_holm": pairwise_mann_whitney(values),
    }
    blocked = {mode: round_aggregates(values[mode]) for mode in MODES}
    blocked_lengths = {len(group) for group in blocked.values()}
    if len(blocked_lengths) == 1 and next(iter(blocked_lengths)) >= 3:
        friedman = stats.friedmanchisquare(*[blocked[mode] for mode in MODES])
        result["friedman_blocked"] = {
            "statistic": float(friedman.statistic),
            "p_value": float(friedman.pvalue),
            "rounds": next(iter(blocked_lengths)),
            "pairwise_wilcoxon_holm": pairwise_wilcoxon(blocked),
        }
    return result


def round_aggregates(values: Sequence[float]) -> List[float]:
    if len(values) == 6:
        return list(values)
    if len(values) % 6 != 0:
        raise ValueError("metric samples cannot be divided into six campaign rounds")
    repetitions_per_round = len(values) // 6
    return [
        statistics.median(values[start : start + repetitions_per_round])
        for start in range(0, len(values), repetitions_per_round)
    ]


def describe(values: Sequence[float]) -> Dict[str, float]:
    from scipy import stats

    sorted_values = sorted(values)
    return {
        "count": len(sorted_values),
        "mean": statistics.fmean(sorted_values),
        "median": statistics.median(sorted_values),
        "minimum": sorted_values[0],
        "maximum": sorted_values[-1],
        "standard_deviation": statistics.stdev(sorted_values)
        if len(sorted_values) > 1
        else 0.0,
        "p95": float(stats.scoreatpercentile(sorted_values, 95)),
    }


def pairwise_mann_whitney(values: Dict[str, List[float]]) -> List[Dict[str, object]]:
    from scipy import stats

    comparisons = []
    for first_index, first in enumerate(MODES):
        for second in MODES[first_index + 1 :]:
            test = stats.mannwhitneyu(
                values[first],
                values[second],
                alternative="two-sided",
                method="auto",
            )
            n_product = len(values[first]) * len(values[second])
            comparisons.append(
                {
                    "first": first,
                    "second": second,
                    "statistic": float(test.statistic),
                    "p_value": float(test.pvalue),
                    "rank_biserial": float(2 * test.statistic / n_product - 1),
                }
            )
    adjusted = holm_adjust([comparison["p_value"] for comparison in comparisons])
    for comparison, adjusted_p in zip(comparisons, adjusted):
        comparison["p_value_holm"] = adjusted_p
        comparison["significant_0_05"] = adjusted_p < 0.05
    return comparisons


def pairwise_wilcoxon(values: Dict[str, List[float]]) -> List[Dict[str, object]]:
    from scipy import stats

    comparisons = []
    for first_index, first in enumerate(MODES):
        for second in MODES[first_index + 1 :]:
            if all(a == b for a, b in zip(values[first], values[second])):
                statistic, p_value = 0.0, 1.0
            else:
                test = stats.wilcoxon(
                    values[first],
                    values[second],
                    alternative="two-sided",
                    zero_method="wilcox",
                    method="auto",
                )
                statistic, p_value = float(test.statistic), float(test.pvalue)
            comparisons.append(
                {
                    "first": first,
                    "second": second,
                    "statistic": statistic,
                    "p_value": p_value,
                }
            )
    adjusted = holm_adjust([comparison["p_value"] for comparison in comparisons])
    for comparison, adjusted_p in zip(comparisons, adjusted):
        comparison["p_value_holm"] = adjusted_p
        comparison["significant_0_05"] = adjusted_p < 0.05
    return comparisons


def holm_adjust(p_values: Sequence[float]) -> List[float]:
    order = sorted(range(len(p_values)), key=lambda index: p_values[index])
    adjusted = [0.0] * len(p_values)
    running_max = 0.0
    count = len(p_values)
    for rank, index in enumerate(order):
        corrected = min(1.0, (count - rank) * p_values[index])
        running_max = max(running_max, corrected)
        adjusted[index] = running_max
    return adjusted


def plot_metric(metric: Metric, values: Dict[str, List[float]], output: Path) -> None:
    import matplotlib.pyplot as plt

    figure, axis = plt.subplots(figsize=(9, 5.2))
    axis.boxplot(
        [values[mode] for mode in MODES],
        labels=[DISPLAY_NAMES[mode] for mode in MODES],
        showmeans=True,
    )
    axis.set_title(metric.label)
    axis.set_ylabel(metric.unit)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=160)
    plt.close(figure)


def render_markdown(
    benchmarks: Dict[str, Dict[str, object]],
    analysis: Dict[str, object],
) -> str:
    lines = [
        "# Statisticka analiza finalne evaluacije",
        "",
        "Analiza koristi jedno benchmark ponavljanje kao statisticku jedinicu za RTT i throughput, a jedan randomizovani blok za server CPU/RAM.",
        "",
        "## Integritet uzorka",
        "",
        "| Rezim | RTT primljeno/ocekivano | ICMP loss | TCP run | UDP run | Retry pokusaji |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in MODES:
        document = benchmarks[mode]
        latency = document["latency"]
        failures = len(document["tcp"].get("failed_attempts", [])) + len(
            document["udp"].get("failed_attempts", [])
        )
        lines.append(
            f"| {DISPLAY_NAMES[mode]} | {latency.get('received_samples', len([v for run in latency['raw_runs'] for v in run['rtt_ms']]))}/{latency.get('expected_samples', 'n/a')} | {latency.get('lost_percent', 0):.3f}% | {len(document['tcp']['raw_runs'])} | {len(document['udp']['raw_runs'])} | {failures} |"
        )
    lines.extend(["", "## Deskriptivni rezultati", ""])
    for metric_key, metric_result in analysis["metrics"].items():
        lines.extend(
            [
                f"### {metric_key}",
                "",
                "| Rezim | n | Mean | Median | p95 | SD | Min-Max |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for mode in MODES:
            item = metric_result["descriptive"][mode]
            lines.append(
                f"| {DISPLAY_NAMES[mode]} | {item['count']} | {item['mean']:.3f} | {item['median']:.3f} | {item['p95']:.3f} | {item['standard_deviation']:.3f} | {item['minimum']:.3f}-{item['maximum']:.3f} |"
            )
        omnibus = metric_result["kruskal_wallis"]
        lines.extend(
            [
                "",
                f"Kruskal-Wallis: H={omnibus['statistic']:.3f}, p={format_p(omnibus['p_value'])}.",
                "",
                f"![{metric_key}]({metric_key}.png)",
                "",
            ]
        )
    lines.extend(
        [
            "## Napomena o interpretaciji",
            "",
            "B2s server je burstable i UDP loss pokazuje vremenski trend u kasnijim rundama kod user-space tunela. Randomizacija smanjuje, ali ne uklanja ovaj uticaj. Zakljucci moraju navesti ogranicenje i odvojiti statisticku od prakticne znacajnosti.",
            "",
        ]
    )
    return "\n".join(lines)


def format_p(value: float) -> str:
    return "<0.001" if value < 0.001 else f"{value:.3f}"


def _load(path: Path) -> Dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load analysis input {path}: {error}") from error


def _analysis_dependencies() -> None:
    try:
        import matplotlib
        import scipy
    except ImportError as error:
        raise RuntimeError(
            "final analysis requires the optional analysis dependencies"
        ) from error
    matplotlib.use("Agg")


if __name__ == "__main__":
    raise SystemExit(main())