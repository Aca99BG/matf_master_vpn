from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.resource_monitor import cpu_percent, process_rss_mib, read_cpu_times, read_memory


class ResourceMonitorTest(unittest.TestCase):
    def test_parses_cpu_and_calculates_utilization(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "stat"
            path.write_text("cpu  100 0 50 850 0 0 0 0\n", encoding="ascii")

            first = read_cpu_times(path)
            utilization = cpu_percent(first, (1200, 1000))

            self.assertEqual(first, (1000, 850))
            self.assertEqual(utilization, 25.0)

    def test_parses_available_memory(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "meminfo"
            path.write_text(
                "MemTotal: 4096 kB\nMemAvailable: 1024 kB\n",
                encoding="ascii",
            )

            self.assertEqual(
                read_memory(path),
                {"total_kib": 4096, "used_kib": 3072},
            )

    def test_sums_rss_for_matching_processes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, rss in (("100", 1024), ("101", 2048)):
                process = root / pid
                process.mkdir()
                (process / "cmdline").write_bytes(b"python\0matf-vpn-server\0")
                (process / "status").write_text(f"Name:\tpython\nVmRSS:\t{rss} kB\n")

            self.assertEqual(process_rss_mib("matf-vpn-server", root), 3.0)
            self.assertIsNone(process_rss_mib("openvpn", root))


if __name__ == "__main__":
    unittest.main()