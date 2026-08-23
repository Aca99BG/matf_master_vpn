"""Merge resource-monitor blocks from a benchmark campaign."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Optional

from matf_vpn.benchmark import summarize


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(arguments)

    samples = []
    source_files = []
    for block_number, path in enumerate(options.input, start=1):
        document = _load(path)
        source_files.append(str(path))
        for sample in document["raw_samples"]:
            samples.append({**sample, "block": block_number})
    result = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": options.label,
        "source_files": source_files,
        "raw_samples": samples,
        "summary": {
            "system_cpu_percent": summarize(
                sample["system_cpu_percent"] for sample in samples
            ).to_dict(),
            "memory_used_mib": summarize(
                sample["memory_used_mib"] for sample in samples
            ).to_dict(),
            "memory_used_percent": summarize(
                sample["memory_used_percent"] for sample in samples
            ).to_dict(),
        },
    }
    process_rss = [
        sample["process_rss_mib"]
        for sample in samples
        if sample.get("process_rss_mib") is not None
    ]
    if process_rss:
        result["summary"]["process_rss_mib"] = summarize(process_rss).to_dict()

    options.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = options.output.with_suffix(options.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(options.output)
    print(options.output)
    return 0


def _load(path: Path) -> Dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load resource block {path}: {error}") from error
    if document.get("schema_version") != 1 or "raw_samples" not in document:
        raise ValueError(f"invalid resource monitor document: {path}")
    return document


if __name__ == "__main__":
    raise SystemExit(main())