"""Parsing and statistical summaries for VPN performance experiments."""

from dataclasses import asdict, dataclass
import json
import math
import re
import statistics
from typing import Dict, Iterable, List


PING_REPLY = re.compile(r"time[=<]([0-9.]+)\s*ms")


@dataclass(frozen=True)
class Summary:
    count: int
    minimum: float
    maximum: float
    mean: float
    median: float
    p95: float
    standard_deviation: float
    confidence_95_low: float
    confidence_95_high: float

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


def summarize(samples: Iterable[float]) -> Summary:
    values = sorted(float(sample) for sample in samples)
    if not values:
        raise ValueError("at least one sample is required")

    count = len(values)
    mean = statistics.fmean(values)
    standard_deviation = statistics.stdev(values) if count > 1 else 0.0
    margin = 1.96 * standard_deviation / math.sqrt(count)
    return Summary(
        count=count,
        minimum=values[0],
        maximum=values[-1],
        mean=mean,
        median=statistics.median(values),
        p95=_percentile(values, 0.95),
        standard_deviation=standard_deviation,
        confidence_95_low=mean - margin,
        confidence_95_high=mean + margin,
    )


def parse_ping_times(output: str) -> List[float]:
    samples = [float(match.group(1)) for match in PING_REPLY.finditer(output)]
    if not samples:
        raise ValueError("ping output contains no RTT samples")
    return samples


def parse_iperf3_json(output: str, protocol: str) -> Dict[str, float]:
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError("iperf3 output is not valid JSON") from error
    if "error" in result:
        raise ValueError(f"iperf3 failed: {result['error']}")

    normalized_protocol = protocol.lower()
    try:
        if normalized_protocol == "tcp":
            summary = result["end"]["sum_received"]
            return {"bits_per_second": float(summary["bits_per_second"])}
        if normalized_protocol == "udp":
            summary = result["end"]["sum"]
            return {
                "bits_per_second": float(summary["bits_per_second"]),
                "jitter_ms": float(summary["jitter_ms"]),
                "lost_percent": float(summary["lost_percent"]),
            }
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("iperf3 JSON does not contain the expected metrics") from error
    raise ValueError("protocol must be tcp or udp")


def _percentile(values: List[float], fraction: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    weight = position - lower
    return values[lower] * (1 - weight) + values[upper] * weight
