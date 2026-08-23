"""Plan and aggregate randomized benchmark campaigns."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Optional

from matf_vpn.experiment import create_balanced_schedule, merge_benchmark_blocks


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    schedule_parser = subparsers.add_parser("schedule")
    schedule_parser.add_argument("--mode", action="append", required=True)
    schedule_parser.add_argument("--rounds", type=int, default=6)
    schedule_parser.add_argument("--repetitions-per-block", type=int, default=5)
    schedule_parser.add_argument("--seed", type=int, required=True)
    schedule_parser.add_argument("--output", type=Path, required=True)

    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument("--label", required=True)
    merge_parser.add_argument("--input", type=Path, action="append", required=True)
    merge_parser.add_argument("--output", type=Path, required=True)

    options = parser.parse_args(arguments)
    if options.command == "schedule":
        schedule = create_balanced_schedule(
            options.mode,
            options.rounds,
            options.repetitions_per_block,
            options.seed,
        )
        document = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "seed": options.seed,
            "modes": options.mode,
            "rounds": options.rounds,
            "repetitions_per_block": options.repetitions_per_block,
            "total_repetitions_per_mode": options.rounds
            * options.repetitions_per_block,
            "blocks": [block.to_dict() for block in schedule],
        }
    else:
        document = merge_benchmark_blocks(options.input, options.label)

    options.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = options.output.with_suffix(options.output.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(options.output)
    print(options.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())