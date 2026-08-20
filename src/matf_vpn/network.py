"""Linux network configuration used by the VPN endpoint."""

import subprocess


def configure_tun(name: str, address: str, mtu: int) -> None:
    if not 576 <= mtu <= 65_535:
        raise ValueError("MTU must be between 576 and 65535")

    subprocess.run(
        ["ip", "address", "add", address, "dev", name],
        check=True,
    )
    subprocess.run(
        ["ip", "link", "set", "dev", name, "mtu", str(mtu), "up"],
        check=True,
    )
