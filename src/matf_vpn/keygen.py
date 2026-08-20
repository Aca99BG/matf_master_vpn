"""Generate an X25519 identity keypair for a VPN endpoint."""

import argparse
from pathlib import Path
from typing import List, Optional

from matf_vpn.key_agreement import write_keypair


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    options = parser.parse_args(arguments)

    write_keypair(options.private_key, options.public_key)
    print(f"Private key: {options.private_key}")
    print(f"Public key: {options.public_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
