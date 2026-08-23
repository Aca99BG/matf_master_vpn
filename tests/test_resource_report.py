import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.resource_report import main


class ResourceReportTest(unittest.TestCase):
    def test_merges_samples_and_recomputes_summary(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for index, cpu in enumerate((10.0, 30.0)):
                path = root / f"block-{index}.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "raw_samples": [
                                {
                                    "elapsed_seconds": 1.0,
                                    "system_cpu_percent": cpu,
                                    "memory_used_mib": 100.0 + index,
                                    "memory_used_percent": 25.0,
                                    "process_rss_mib": None,
                                }
                            ],
                        }
                    )
                )
                inputs.extend(["--input", str(path)])
            output = root / "merged.json"

            main(["--label", "wireguard", *inputs, "--output", str(output)])

            result = json.loads(output.read_text())
            self.assertEqual(len(result["raw_samples"]), 2)
            self.assertEqual(result["summary"]["system_cpu_percent"]["mean"], 20.0)


if __name__ == "__main__":
    unittest.main()