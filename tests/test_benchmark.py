import json
import unittest

from matf_vpn.benchmark import parse_iperf3_json, parse_ping_times, summarize


class BenchmarkParsingTest(unittest.TestCase):
    def test_parses_individual_ping_samples(self) -> None:
        output = """
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.402 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.474 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.335 ms
"""

        self.assertEqual(parse_ping_times(output), [0.402, 0.474, 0.335])

    def test_summarizes_samples(self) -> None:
        summary = summarize([1, 2, 3, 4, 5])

        self.assertEqual(summary.count, 5)
        self.assertEqual(summary.mean, 3.0)
        self.assertEqual(summary.median, 3.0)
        self.assertAlmostEqual(summary.p95, 4.8)
        self.assertLess(summary.confidence_95_low, summary.mean)
        self.assertGreater(summary.confidence_95_high, summary.mean)

    def test_parses_tcp_iperf3_json(self) -> None:
        output = json.dumps(
            {"end": {"sum_received": {"bits_per_second": 123456789.0}}}
        )

        self.assertEqual(
            parse_iperf3_json(output, "tcp"),
            {"bits_per_second": 123456789.0},
        )

    def test_parses_udp_iperf3_json(self) -> None:
        output = json.dumps(
            {
                "end": {
                    "sum": {
                        "bits_per_second": 50000000.0,
                        "jitter_ms": 0.12,
                        "lost_percent": 0.5,
                    }
                }
            }
        )

        self.assertEqual(
            parse_iperf3_json(output, "udp"),
            {
                "bits_per_second": 50000000.0,
                "jitter_ms": 0.12,
                "lost_percent": 0.5,
            },
        )


if __name__ == "__main__":
    unittest.main()