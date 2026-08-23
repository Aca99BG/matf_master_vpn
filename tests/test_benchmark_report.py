import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.benchmark_report import main


def result(label: str, latency: float, tcp_bps: float):
    return {
        "schema_version": 1,
        "label": label,
        "latency": {"summary": {"median": latency, "p95": latency * 1.2}},
        "tcp": {"raw_runs": [{"bits_per_second": tcp_bps}]},
        "udp": {
            "raw_runs": [
                {
                    "bits_per_second": tcp_bps / 2,
                    "jitter_ms": 0.2,
                    "lost_percent": 0.5,
                }
            ]
        },
    }


class BenchmarkReportTest(unittest.TestCase):
    def test_compares_result_with_baseline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "direct.json"
            vpn = root / "vpn.json"
            output = root / "report.csv"
            baseline.write_text(json.dumps(result("direct", 1.0, 100_000_000)))
            vpn.write_text(json.dumps(result("vpn", 1.5, 80_000_000)))

            main(
                [
                    "--baseline",
                    str(baseline),
                    "--result",
                    str(vpn),
                    "--output",
                    str(output),
                ]
            )

            with output.open(encoding="utf-8") as report_file:
                rows = list(csv.DictReader(report_file))
            self.assertEqual(rows[1]["label"], "vpn")
            self.assertEqual(float(rows[1]["latency_overhead_percent"]), 50.0)
            self.assertEqual(float(rows[1]["tcp_mean_mbps"]), 80.0)
            self.assertEqual(float(rows[1]["tcp_change_percent"]), -20.0)

    def test_includes_resource_metrics(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "direct.json"
            resource = root / "resource.json"
            output = root / "report.csv"
            baseline.write_text(json.dumps(result("direct", 1.0, 100_000_000)))
            resource.write_text(
                json.dumps(
                    {
                        "summary": {
                            "system_cpu_percent": {"mean": 12.0, "p95": 25.0},
                            "memory_used_mib": {"mean": 512.0, "p95": 530.0},
                        }
                    }
                )
            )

            main(
                [
                    "--baseline",
                    str(baseline),
                    "--resource",
                    f"direct={resource}",
                    "--output",
                    str(output),
                ]
            )

            with output.open(encoding="utf-8") as report_file:
                row = next(csv.DictReader(report_file))
            self.assertEqual(float(row["server_cpu_mean_percent"]), 12.0)
            self.assertEqual(float(row["server_memory_p95_mib"]), 530.0)


if __name__ == "__main__":
    unittest.main()