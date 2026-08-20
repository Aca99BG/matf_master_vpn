"""Typed JSON configuration for a VPN endpoint."""

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from matf_vpn.crypto import EndpointRole
from matf_vpn.transport import Address


ALLOWED_FIELDS = {
    "tun_name",
    "tun_address",
    "mtu",
    "bind",
    "peer",
    "session_id",
    "key_file",
    "private_key_file",
    "peer_public_key_file",
    "role",
    "ephemeral_handshake",
    "handshake_timeout",
    "packets_per_key",
    "reconnect_delay",
    "json_logs",
    "keepalive_interval",
    "liveness_timeout",
}


@dataclass(frozen=True)
class EndpointConfig:
    tun_name: str
    tun_address: str
    bind: Address
    peer: Address
    mtu: int = 1400
    session_id: int = 1
    key_file: Optional[Path] = None
    private_key_file: Optional[Path] = None
    peer_public_key_file: Optional[Path] = None
    role: Optional[EndpointRole] = None
    ephemeral_handshake: bool = False
    handshake_timeout: float = 3.0
    packets_per_key: int = 0
    reconnect_delay: float = 1.0
    json_logs: bool = False
    keepalive_interval: float = 0.0
    liveness_timeout: float = 0.0


def load_config(path: Path) -> EndpointConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load configuration: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a JSON object")

    unknown = set(raw) - ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"unknown configuration fields: {', '.join(sorted(unknown))}")
    for required in ("tun_address", "bind", "peer"):
        if required not in raw:
            raise ValueError(f"missing required configuration field: {required}")

    base_directory = path.parent
    role = _optional_string(raw, "role")
    try:
        parsed_role = EndpointRole(role) if role is not None else None
    except ValueError as error:
        raise ValueError("role must be client or server") from error

    config = EndpointConfig(
        tun_name=_string(raw, "tun_name", "mvpn0"),
        tun_address=_string(raw, "tun_address"),
        bind=_endpoint(raw["bind"], "bind"),
        peer=_endpoint(raw["peer"], "peer"),
        mtu=_integer(raw, "mtu", 1400),
        session_id=_integer(raw, "session_id", 1),
        key_file=_path(raw, "key_file", base_directory),
        private_key_file=_path(raw, "private_key_file", base_directory),
        peer_public_key_file=_path(raw, "peer_public_key_file", base_directory),
        role=parsed_role,
        ephemeral_handshake=_boolean(raw, "ephemeral_handshake", False),
        handshake_timeout=_number(raw, "handshake_timeout", 3.0),
        packets_per_key=_integer(raw, "packets_per_key", 0),
        reconnect_delay=_number(raw, "reconnect_delay", 1.0),
        json_logs=_boolean(raw, "json_logs", False),
        keepalive_interval=_number(raw, "keepalive_interval", 0.0),
        liveness_timeout=_number(raw, "liveness_timeout", 0.0),
    )
    _validate(config)
    return config


def _validate(config: EndpointConfig) -> None:
    try:
        ipaddress.IPv4Interface(config.tun_address)
    except ValueError as error:
        raise ValueError("tun_address must be an IPv4 interface in CIDR notation") from error
    if not config.tun_name or len(config.tun_name.encode("ascii")) > 15:
        raise ValueError("tun_name must contain 1 to 15 ASCII bytes")
    if not 576 <= config.mtu <= 65_535:
        raise ValueError("mtu must be between 576 and 65535")
    if not 0 <= config.session_id <= 0xFFFFFFFF:
        raise ValueError("session_id must fit in 32 bits")
    if config.handshake_timeout <= 0 or config.reconnect_delay < 0:
        raise ValueError("timeouts and reconnect delay must be valid")
    if config.packets_per_key < 0:
        raise ValueError("packets_per_key must not be negative")
    if config.keepalive_interval < 0 or config.liveness_timeout < 0:
        raise ValueError("liveness values must not be negative")
    if bool(config.keepalive_interval) != bool(config.liveness_timeout):
        raise ValueError("keepalive_interval and liveness_timeout must be enabled together")
    if config.liveness_timeout and config.liveness_timeout <= config.keepalive_interval:
        raise ValueError("liveness_timeout must be greater than keepalive_interval")

    uses_psk = config.key_file is not None
    uses_x25519 = config.private_key_file is not None or config.peer_public_key_file is not None
    if uses_psk and uses_x25519:
        raise ValueError("PSK and X25519 key options are mutually exclusive")
    if uses_x25519 and (
        config.private_key_file is None or config.peer_public_key_file is None
    ):
        raise ValueError("both X25519 key files are required")
    encrypted = uses_psk or uses_x25519
    if encrypted != (config.role is not None):
        raise ValueError("role is required exactly when encryption is enabled")
    if config.ephemeral_handshake and not uses_x25519:
        raise ValueError("ephemeral_handshake requires X25519 key files")
    if config.packets_per_key > 0 and not encrypted:
        raise ValueError("packets_per_key requires encryption")
    if config.liveness_timeout and not config.ephemeral_handshake:
        raise ValueError("active liveness requires ephemeral_handshake")


def _endpoint(value: Any, field: str) -> Address:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IPv4_ADDRESS:PORT string")
    try:
        host, raw_port = value.rsplit(":", 1)
        host = str(ipaddress.IPv4Address(host))
        port = int(raw_port)
    except ValueError as error:
        raise ValueError(f"{field} must be an IPv4_ADDRESS:PORT string") from error
    if not 1 <= port <= 65_535:
        raise ValueError(f"{field} port must be between 1 and 65535")
    return host, port


def _string(raw: Dict[str, Any], field: str, default: Optional[str] = None) -> str:
    value = raw.get(field, default)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _optional_string(raw: Dict[str, Any], field: str) -> Optional[str]:
    value = raw.get(field)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _integer(raw: Dict[str, Any], field: str, default: int) -> int:
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def _number(raw: Dict[str, Any], field: str, default: float) -> float:
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    return float(value)


def _boolean(raw: Dict[str, Any], field: str, default: bool) -> bool:
    value = raw.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _path(raw: Dict[str, Any], field: str, base_directory: Path) -> Optional[Path]:
    value = raw.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a path string")
    path = Path(value)
    return path if path.is_absolute() else base_directory / path
