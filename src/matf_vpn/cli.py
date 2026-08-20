"""Command-line entry point for a point-to-point VPN endpoint."""

import argparse
import ipaddress
import logging
from pathlib import Path
import stat
import sys
from typing import List, Optional

from matf_vpn.config import EndpointConfig, load_config
from matf_vpn.crypto import EndpointRole, create_cipher
from matf_vpn.engine import TunnelEngine
from matf_vpn.handshake import run_client_handshake, run_server_handshake
from matf_vpn.key_agreement import X25519_KEY_SIZE, derive_shared_secret
from matf_vpn.network import configure_tun
from matf_vpn.operations import configure_logging, run_with_reconnect
from matf_vpn.transport import Address, UdpTransport
from matf_vpn.tun import TunDevice


def parse_endpoint(value: str) -> Address:
    try:
        host, raw_port = value.rsplit(":", 1)
        host = str(ipaddress.IPv4Address(host))
        port = int(raw_port)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("endpoint must be IPv4_ADDRESS:PORT") from error

    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return host, port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--tun-name", default="mvpn0")
    parser.add_argument("--tun-address")
    parser.add_argument("--mtu", type=int, default=1400)
    parser.add_argument("--bind", type=parse_endpoint)
    parser.add_argument("--peer", type=parse_endpoint)
    parser.add_argument("--session-id", type=int, default=1)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--peer-public-key-file", type=Path)
    parser.add_argument("--role", choices=[role.value for role in EndpointRole])
    parser.add_argument("--ephemeral-handshake", action="store_true")
    parser.add_argument("--handshake-timeout", type=float, default=3.0)
    parser.add_argument("--packets-per-key", type=int, default=0)
    parser.add_argument("--reconnect-delay", type=float, default=1.0)
    parser.add_argument("--json-logs", action="store_true")
    parser.add_argument("--keepalive-interval", type=float, default=0.0)
    parser.add_argument("--liveness-timeout", type=float, default=0.0)
    return parser


def parse_options(arguments: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    options = parser.parse_args(arguments)
    raw_arguments = arguments if arguments is not None else sys.argv[1:]
    if options.config is not None:
        config_forms = {"--config", f"--config={options.config}"}
        non_config_arguments = [
            argument
            for argument in raw_arguments
            if argument not in config_forms and argument != str(options.config)
        ]
        if non_config_arguments:
            parser.error("--config cannot be combined with endpoint options")
        return _namespace_from_config(load_config(options.config))
    if options.tun_address is None or options.bind is None or options.peer is None:
        parser.error("--tun-address, --bind, and --peer are required without --config")
    return options


def _namespace_from_config(config: EndpointConfig) -> argparse.Namespace:
    return argparse.Namespace(
        config=None,
        tun_name=config.tun_name,
        tun_address=config.tun_address,
        mtu=config.mtu,
        bind=config.bind,
        peer=config.peer,
        session_id=config.session_id,
        key_file=config.key_file,
        private_key_file=config.private_key_file,
        peer_public_key_file=config.peer_public_key_file,
        role=config.role.value if config.role is not None else None,
        ephemeral_handshake=config.ephemeral_handshake,
        handshake_timeout=config.handshake_timeout,
        packets_per_key=config.packets_per_key,
        reconnect_delay=config.reconnect_delay,
        json_logs=config.json_logs,
        keepalive_interval=config.keepalive_interval,
        liveness_timeout=config.liveness_timeout,
    )


def load_preshared_key(path: Path) -> bytes:
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise ValueError("cannot access key file") from error
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("key file must not be accessible by group or other users")

    try:
        key = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("key file must contain a hexadecimal preshared key") from error
    if len(key) < 32:
        raise ValueError("key file must contain at least 32 bytes")
    return key


def load_x25519_key(path: Path, private: bool) -> bytes:
    if private:
        try:
            mode = path.stat().st_mode
        except OSError as error:
            raise ValueError("cannot access X25519 private key file") from error
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("X25519 private key must not be accessible by group or other users")

    label = "private" if private else "public"
    try:
        key = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"X25519 {label} key file must contain hexadecimal data") from error
    if len(key) != X25519_KEY_SIZE:
        raise ValueError(f"X25519 {label} key must contain 32 bytes")
    return key


def main(arguments: Optional[List[str]] = None) -> int:
    options = parse_options(arguments)
    configure_logging(json_output=options.json_logs)
    logger = logging.getLogger("matf_vpn")
    uses_preshared_key = options.key_file is not None
    uses_x25519 = (
        options.private_key_file is not None or options.peer_public_key_file is not None
    )
    if uses_preshared_key and uses_x25519:
        raise SystemExit("PSK and X25519 key options are mutually exclusive")
    if uses_x25519 and (
        options.private_key_file is None or options.peer_public_key_file is None
    ):
        raise SystemExit("--private-key-file and --peer-public-key-file must be provided together")
    uses_encryption = uses_preshared_key or uses_x25519
    if uses_encryption != (options.role is not None):
        raise SystemExit("--role is required exactly when encryption is enabled")
    if options.ephemeral_handshake and not uses_x25519:
        raise SystemExit("--ephemeral-handshake requires X25519 key files")
    if options.handshake_timeout <= 0:
        raise SystemExit("--handshake-timeout must be positive")
    if options.packets_per_key < 0:
        raise SystemExit("--packets-per-key must not be negative")
    if options.reconnect_delay < 0:
        raise SystemExit("--reconnect-delay must not be negative")
    if options.packets_per_key > 0 and not uses_encryption:
        raise SystemExit("--packets-per-key requires encryption")
    if options.keepalive_interval < 0 or options.liveness_timeout < 0:
        raise SystemExit("liveness values must not be negative")
    if bool(options.keepalive_interval) != bool(options.liveness_timeout):
        raise SystemExit("keepalive and liveness timeout must be enabled together")
    if options.liveness_timeout and options.liveness_timeout <= options.keepalive_interval:
        raise SystemExit("liveness timeout must be greater than keepalive interval")
    if options.liveness_timeout and not options.ephemeral_handshake:
        raise SystemExit("active liveness requires --ephemeral-handshake")

    cipher = None
    static_private_key = None
    peer_static_public_key = None
    if uses_preshared_key:
        cipher = create_cipher(
            load_preshared_key(options.key_file),
            options.session_id,
            EndpointRole(options.role),
            options.packets_per_key,
        )
    elif uses_x25519:
        static_private_key = load_x25519_key(options.private_key_file, private=True)
        peer_static_public_key = load_x25519_key(
            options.peer_public_key_file,
            private=False,
        )
        if not options.ephemeral_handshake:
            shared_secret = derive_shared_secret(
                static_private_key,
                peer_static_public_key,
            )
            cipher = create_cipher(
                shared_secret,
                options.session_id,
                EndpointRole(options.role),
                options.packets_per_key,
            )

    def run_session() -> None:
        transport_timeout = options.handshake_timeout if options.ephemeral_handshake else None
        with UdpTransport(options.bind, timeout=transport_timeout) as transport:
            session_id = options.session_id
            session_cipher = cipher
            if options.ephemeral_handshake:
                handshake = (
                    run_client_handshake
                    if options.role == EndpointRole.CLIENT.value
                    else run_server_handshake
                )
                session_id, session_cipher = handshake(
                    transport,
                    options.peer,
                    static_private_key,
                    peer_static_public_key,
                    packets_per_key=options.packets_per_key,
                )
                transport.set_timeout(None)

            with TunDevice(options.tun_name) as tun_device:
                configure_tun(tun_device.name, options.tun_address, options.mtu)
                logger.info(
                    "VPN session established",
                    extra={
                        "event": "session_established",
                        "tun_name": tun_device.name,
                        "tun_address": options.tun_address,
                        "bind_address": f"{transport.local_address[0]}:{transport.local_address[1]}",
                        "peer_address": f"{options.peer[0]}:{options.peer[1]}",
                        "session_id": session_id,
                        "encrypted": session_cipher is not None,
                        "ephemeral_handshake": options.ephemeral_handshake,
                        "packets_per_key": options.packets_per_key,
                    },
                )
                TunnelEngine(
                    tun_device,
                    transport,
                    options.peer,
                    session_id,
                    session_cipher,
                    options.keepalive_interval,
                    options.liveness_timeout,
                ).run()

    try:
        if options.ephemeral_handshake:
            run_with_reconnect(
                run_session,
                options.reconnect_delay,
                logger,
            )
        else:
            run_session()
    except KeyboardInterrupt:
        logger.info("VPN endpoint stopped", extra={"event": "endpoint_stopped"})
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
