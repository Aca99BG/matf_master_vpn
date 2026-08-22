import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from matf_vpn.benchmark_cli import BenchmarkCommandError, _run, main


PING_OUTPUT = """
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.100 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.200 ms
"""


class BenchmarkRunnerTest(unittest.TestCase):
    @patch("matf_vpn.benchmark_cli._run", return_value=PING_OUTPUT)
    def test_writes_raw_latency_runs_and_summary(self, run_mock) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "latency.json"

            result = main(
                [
                    "--label",
                    "plaintext",
                    "--target",
                    "127.0.0.1",
                    "--output",
                    str(output),
                    "--repetitions",
                    "2",
                    "--ping-count",
                    "2",
                    "--skip-iperf",
                ]
            )

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["label"], "plaintext")
            self.assertEqual(len(document["latency"]["raw_runs"]), 2)
            self.assertEqual(document["latency"]["summary"]["count"], 4)
            self.assertEqual(run_mock.call_count, 2)

    @patch("matf_vpn.benchmark_cli._run")
    @patch("matf_vpn.benchmark_cli.shutil.which", return_value="/usr/bin/iperf3")
    def test_collects_tcp_and_udp_runs(self, which_mock, run_mock) -> None:
        run_mock.side_effect = [
            PING_OUTPUT,
            json.dumps({"end": {"sum_received": {"bits_per_second": 10.0}}}),
            json.dumps(
                {
                    "end": {
                        "sum": {
                            "bits_per_second": 9.0,
                            "jitter_ms": 0.1,
                            "lost_percent": 0.0,
                        }
                    }
                }
            ),
        ]
        with TemporaryDirectory() as directory:
            output = Path(directory) / "all.json"

            main(
                [
                    "--label",
                    "encrypted",
                    "--target",
                    "10.0.0.2",
                    "--output",
                    str(output),
                    "--repetitions",
                    "1",
                    "--ping-count",
                    "2",
                ]
            )

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["tcp"]["raw_runs"][0]["bits_per_second"], 10.0)
            self.assertEqual(document["udp"]["raw_runs"][0]["jitter_ms"], 0.1)

    @patch("matf_vpn.benchmark_cli.subprocess.run")
    def test_reports_failed_external_command(self, run_mock) -> None:
        run_mock.return_value = Mock(returncode=2, stderr="permission denied", stdout="")

        with self.assertRaisesRegex(
            BenchmarkCommandError,
            "exit 2: ping 127.0.0.1\\npermission denied",
        ):
            _run(["ping", "127.0.0.1"])

    @patch("matf_vpn.benchmark_cli.time.sleep")
    @patch("matf_vpn.benchmark_cli._run")
    @patch("matf_vpn.benchmark_cli.shutil.which", return_value="/usr/bin/iperf3")
    def test_retries_and_records_transient_iperf_failure(
        self,
        which_mock,
        run_mock,
        sleep_mock,
    ) -> None:
        run_mock.side_effect = [
            PING_OUTPUT,
            BenchmarkCommandError("control connection reset"),
            json.dumps({"end": {"sum_received": {"bits_per_second": 10.0}}}),
            json.dumps(
                {
                    "end": {
                        "sum": {
                            "bits_per_second": 9.0,
                            "jitter_ms": 0.1,
                            "lost_percent": 0.0,
                        }
                    }
                }
            ),
        ]
        with TemporaryDirectory() as directory:
            output = Path(directory) / "retried.json"

            main(
                [
                    "--label",
                    "azure",
                    "--target",
                    "10.8.0.1",
                    "--output",
                    str(output),
                    "--repetitions",
                    "1",
                    "--ping-count",
                    "2",
                    "--inter-run-delay",
                    "0",
                ]
            )

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(document["tcp"]["failed_attempts"]), 1)
            self.assertIn("control connection reset", document["tcp"]["failed_attempts"][0]["error"])


if __name__ == "__main__":
    unittest.main()