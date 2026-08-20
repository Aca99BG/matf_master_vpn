"""Authenticated multi-client VPN server runtime."""

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
import select
from typing import Iterable, Optional, Tuple

from matf_vpn.crypto import EndpointRole, create_cipher
from matf_vpn.handshake import accept_client_hello
from matf_vpn.multi_client import ClientSession, MultiClientServerEngine
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet
from matf_vpn.transport import Address, UdpTransport
from matf_vpn.tun import TunDevice


@dataclass(frozen=True)
class ClientIdentity:
    name: str
    tunnel_address: ipaddress.IPv4Address
    public_key: bytes


HANDSHAKE_CACHE_SIZE = 1024


@dataclass(frozen=True)
class AcceptedSession:
    response: Packet
    session: ClientSession
    identity: ClientIdentity
    is_new: bool


class ClientRegistry:
    def __init__(
        self,
        server_private_key: bytes,
        clients: Iterable[ClientIdentity],
        packets_per_key: int = 0,
    ) -> None:
        self._server_private_key = server_private_key
        self._clients = tuple(clients)
        self._packets_per_key = packets_per_key
        self._accepted_hellos: "OrderedDict[bytes, AcceptedSession]" = OrderedDict()
        names = [client.name for client in self._clients]
        addresses = [client.tunnel_address for client in self._clients]
        if len(set(names)) != len(names):
            raise ValueError("client names must be unique")
        if len(set(addresses)) != len(addresses):
            raise ValueError("client tunnel addresses must be unique")

    def accept(self, packet: Packet, remote_address: Address) -> Optional[AcceptedSession]:
        if packet.message_type is not MessageType.CLIENT_HELLO:
            return None
        fingerprint = hashlib.sha256(packet.encode()).digest()
        cached = self._accepted_hellos.get(fingerprint)
        if cached is not None:
            self._accepted_hellos.move_to_end(fingerprint)
            return AcceptedSession(
                cached.response,
                cached.session,
                cached.identity,
                is_new=False,
            )
        for identity in self._clients:
            try:
                response, session_secret = accept_client_hello(
                    packet,
                    self._server_private_key,
                    identity.public_key,
                )
            except ValueError:
                continue
            cipher = create_cipher(
                session_secret,
                packet.session_id,
                EndpointRole.SERVER,
                self._packets_per_key,
            )
            session = ClientSession(
                remote_address,
                identity.tunnel_address,
                packet.session_id,
                cipher,
            )
            accepted = AcceptedSession(response, session, identity, is_new=True)
            self._accepted_hellos[fingerprint] = accepted
            if len(self._accepted_hellos) > HANDSHAKE_CACHE_SIZE:
                self._accepted_hellos.popitem(last=False)
            return accepted
        return None


class MultiClientServer:
    def __init__(
        self,
        tun_device: TunDevice,
        transport: UdpTransport,
        registry: ClientRegistry,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._tun_device = tun_device
        self._transport = transport
        self._registry = registry
        self._engine = MultiClientServerEngine(tun_device, transport)
        self._logger = logger or logging.getLogger("matf_vpn.multi_server")

    def run(self) -> None:
        while True:
            self.run_once()

    def run_once(self, timeout: Optional[float] = None) -> int:
        readable, _, _ = select.select(
            [self._tun_device.fileno(), self._transport.fileno()],
            [],
            [],
            timeout,
        )
        forwarded = 0
        if self._tun_device.fileno() in readable:
            forwarded += int(self._engine.handle_tun_packet(self._tun_device.read()))
        if self._transport.fileno() in readable:
            try:
                packet, remote_address = self._transport.receive()
            except InvalidPacketError:
                return forwarded
            accepted = self._registry.accept(packet, remote_address)
            if accepted is not None:
                self._transport.send(accepted.response, remote_address)
                if accepted.is_new:
                    self._engine.replace_session(accepted.session)
                    self._logger.info(
                        "VPN client session established",
                        extra={
                            "event": "client_session_established",
                            "client": accepted.identity.name,
                            "tunnel_address": str(accepted.identity.tunnel_address),
                            "session_id": accepted.session.session_id,
                            "remote_address": f"{remote_address[0]}:{remote_address[1]}",
                        },
                    )
            else:
                forwarded += int(self._engine.handle_udp_packet(packet, remote_address))
        return forwarded
