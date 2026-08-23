import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.experiment import create_balanced_schedule, merge_benchmark_blocks


class BalancedScheduleTest(unittest.TestCase):
    def test_is_deterministic_and_balanced(self) -> None:
        modes = ["direct", "python", "wireguard", "openvpn"]

        first = create_balanced_schedule(modes, rounds=6, repetitions_per_block=5, seed=42)
        second = create_balanced_schedule(modes, rounds=6, repetitions_per_block=5, seed=42)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 24)
        for mode in modes:
            blocks = [block for block in first if block.mode == mode]
            self.assertEqual(len(blocks), 6)
            self.assertEqual(sum(block.repetitions for block in blocks), 30)

    def test_each_round_contains_every_mode_once(self) -> None:
        modes = ["direct", "python", "wireguard", "openvpn"]
        schedule = create_balanced_schedule(modes, 4, 5, seed=7)

        for round_number in range(1, 5):
            round_modes = {
                block.mode for block in schedule if block.round_number == round_number
            }
            self.assertEqual(round_modes, set(modes))

    def test_avoids_same_mode_across_round_boundary(self) -> None:
        schedule = create_balanced_schedule(["a", "b", "c"], 10, 1, seed=9)

        for index in range(2, len(schedule), 3):
            if index + 1 < len(schedule):
                self.assertNotEqual(schedule[index].mode, schedule[index + 1].mode)


def benchmark_block(target: str, rtt: float, throughput: float):
    summary = {
        "count": 1,
        "minimum": rtt,
        "maximum": rtt,
        "mean": rtt,
        "median": rtt,
        "p95": rtt,
        "standard_deviation": 0.0,
        "confidence_95_low": rtt,
        "confidence_95_high": rtt,
    }
    return {
        "schema_version": 1,
        "created_at": "2026-01-01T00:00:00+00:00",
        "label": "block",
        "parameters": {
            "target": target,
            "repetitions": 1,
            "ping_count": 1,
            "iperf_port": 5201,
            "iperf_duration": 10,
            "udp_bitrate": "20M",
            "skip_iperf": False,
        },
        "environment": {"hostname": "client"},
        "latency": {
            "unit": "ms",
            "raw_runs": [{"repetition": 1, "rtt_ms": [rtt]}],
            "summary": summary,
        },
        "tcp": {
            "raw_runs": [{"repetition": 1, "bits_per_second": throughput}],
            "failed_attempts": [],
            "throughput_summary_bps": summary,
        },
        "udp": {
            "raw_runs": [
                {
                    "repetition": 1,
                    "bits_per_second": throughput,
                    "jitter_ms": 1.0,
                    "lost_percent": 0.0,
                }
            ],
            "failed_attempts": [],
            "throughput_summary_bps": summary,
        },
    }


class MergeBenchmarkBlocksTest(unittest.TestCase):
    def test_merges_raw_runs_and_recomputes_summaries(self) -> None:
        with TemporaryDirectory() as directory:
            paths = []
            for index, (rtt, throughput) in enumerate(((10.0, 100.0), (20.0, 200.0))):
                path = Path(directory) / f"block-{index}.json"
                path.write_text(json.dumps(benchmark_block("10.0.0.1", rtt, throughput)))
                paths.append(path)

            merged = merge_benchmark_blocks(paths, "python-final")

            self.assertEqual(merged["parameters"]["repetitions"], 2)
            self.assertEqual(merged["latency"]["summary"]["mean"], 15.0)
            self.assertEqual(merged["tcp"]["throughput_summary_bps"]["mean"], 150.0)
            self.assertEqual(merged["tcp"]["raw_runs"][1]["block"], 2)

    def test_rejects_blocks_with_different_targets(self) -> None:
        with TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first.write_text(json.dumps(benchmark_block("10.0.0.1", 10.0, 100.0)))
            second.write_text(json.dumps(benchmark_block("10.0.0.2", 10.0, 100.0)))

            with self.assertRaisesRegex(ValueError, "parameter: target"):
                merge_benchmark_blocks([first, second], "invalid")


if __name__ == "__main__":
    unittest.main()