"""JSON configuration for the multi-client VPN server."""

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Tuple

from matf_vpn.transport import Address


SERVER_FIELDS = {
    "tun_name",
    "tun_address",
    "mtu",
    "bind",
    "private_key_file",
    "packets_per_key",
    "json_logs",
    "clients",
}
CLIENT_FIELDS = {"name", "tunnel_address", "public_key_file"}


@dataclass(frozen=True)
class ServerClientConfig:
    name: str
    tunnel_address: ipaddress.IPv4Address
    public_key_file: Path


@dataclass(frozen=True)
class MultiClientServerConfig:
    tun_name: str
    tun_address: str
    bind: Address
    private_key_file: Path
    clients: Tuple[ServerClientConfig, ...]
    mtu: int = 1400
    packets_per_key: int = 0
    json_logs: bool = False


def load_server_config(path: Path) -> MultiClientServerConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load server configuration: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError("server configuration root must be a JSON object")
    unknown = set(raw) - SERVER_FIELDS
    if unknown:
        raise ValueError(f"unknown server fields: {', '.join(sorted(unknown))}")
    for required in ("tun_address", "bind", "private_key_file", "clients"):
        if required not in raw:
            raise ValueError(f"missing required server field: {required}")

    base_directory = path.parent
    clients_raw = raw["clients"]
    if not isinstance(clients_raw, list) or not clients_raw:
        raise ValueError("clients must be a non-empty array")
    clients = tuple(_client_config(value, base_directory) for value in clients_raw)
    config = MultiClientServerConfig(
        tun_name=_string(raw, "tun_name", "mvpn0"),
        tun_address=_string(raw, "tun_address"),
        bind=_endpoint(raw["bind"]),
        private_key_file=_path(raw["private_key_file"], base_directory),
        clients=clients,
        mtu=_integer(raw, "mtu", 1400),
        packets_per_key=_integer(raw, "packets_per_key", 0),
        json_logs=_boolean(raw, "json_logs", False),
    )
    _validate(config)
    return config


def _client_config(value: Any, base_directory: Path) -> ServerClientConfig:
    if not isinstance(value, dict):
        raise ValueError("each client must be an object")
    unknown = set(value) - CLIENT_FIELDS
    if unknown:
        raise ValueError(f"unknown client fields: {', '.join(sorted(unknown))}")
    for required in CLIENT_FIELDS:
        if required not in value:
            raise ValueError(f"missing required client field: {required}")
    try:
        tunnel_address = ipaddress.IPv4Address(value["tunnel_address"])
    except (ValueError, TypeError) as error:
        raise ValueError("client tunnel_address must be an IPv4 address") from error
    return ServerClientConfig(
        _string(value, "name"),
        tunnel_address,
        _path(value["public_key_file"], base_directory),
    )


def _validate(config: MultiClientServerConfig) -> None:
    try:
        interface = ipaddress.IPv4Interface(config.tun_address)
    except ValueError as error:
        raise ValueError("tun_address must be an IPv4 interface in CIDR notation") from error
    if not config.tun_name or len(config.tun_name.encode("ascii")) > 15:
        raise ValueError("tun_name must contain 1 to 15 ASCII bytes")
    if not 576 <= config.mtu <= 65_535:
        raise ValueError("mtu must be between 576 and 65535")
    if config.packets_per_key < 0:
        raise ValueError("packets_per_key must not be negative")
    names = [client.name for client in config.clients]
    addresses = [client.tunnel_address for client in config.clients]
    if len(set(names)) != len(names):
        raise ValueError("client names must be unique")
    if len(set(addresses)) != len(addresses):
        raise ValueError("client tunnel addresses must be unique")
    for address in addresses:
        if address not in interface.network or address == interface.ip:
            raise ValueError("client tunnel address must be inside the server TUN network")


def _string(raw: Dict[str, Any], field: str, default: Any = None) -> str:
    value = raw.get(field, default)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _integer(raw: Dict[str, Any], field: str, default: int) -> int:
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def _boolean(raw: Dict[str, Any], field: str, default: bool) -> bool:
    value = raw.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _endpoint(value: Any) -> Address:
    if not isinstance(value, str):
        raise ValueError("bind must be an IPv4_ADDRESS:PORT string")
    try:
        host, raw_port = value.rsplit(":", 1)
        host = str(ipaddress.IPv4Address(host))
        port = int(raw_port)
    except ValueError as error:
        raise ValueError("bind must be an IPv4_ADDRESS:PORT string") from error
    if not 1 <= port <= 65_535:
        raise ValueError("bind port must be between 1 and 65535")
    return host, port


def _path(value: Any, base_directory: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("key file must be a path string")
    path = Path(value)
    return path if path.is_absolute() else base_directory / path
