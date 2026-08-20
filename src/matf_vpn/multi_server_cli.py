"""Command-line entry point for the multi-client VPN server."""

import argparse
import ipaddress
import logging
from pathlib import Path
from typing import List, Optional

from matf_vpn.cli import load_x25519_key
from matf_vpn.multi_server import ClientIdentity, ClientRegistry, MultiClientServer
from matf_vpn.network import configure_tun
from matf_vpn.operations import configure_logging
from matf_vpn.server_config import load_server_config
from matf_vpn.transport import UdpTransport
from matf_vpn.tun import TunDevice


def main(arguments: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    options = parser.parse_args(arguments)
    config = load_server_config(options.config)
    configure_logging(config.json_logs)
    logger = logging.getLogger("matf_vpn.multi_server")

    private_key = load_x25519_key(config.private_key_file, private=True)
    identities = [
        ClientIdentity(
            client.name,
            ipaddress.IPv4Address(client.tunnel_address),
            load_x25519_key(client.public_key_file, private=False),
        )
        for client in config.clients
    ]
    registry = ClientRegistry(private_key, identities, config.packets_per_key)

    try:
        with UdpTransport(config.bind) as transport:
            with TunDevice(config.tun_name) as tun_device:
                configure_tun(tun_device.name, config.tun_address, config.mtu)
                logger.info(
                    "Multi-client VPN server ready",
                    extra={
                        "event": "multi_server_ready",
                        "tun_name": tun_device.name,
                        "tun_address": config.tun_address,
                        "client_capacity": len(identities),
                    },
                )
                MultiClientServer(
                    tun_device,
                    transport,
                    registry,
                    logger,
                ).run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
