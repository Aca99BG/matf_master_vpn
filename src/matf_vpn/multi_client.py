"""Multi-client VPN server data plane."""

from dataclasses import dataclass, field
import ipaddress
import select
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag

from matf_vpn.crypto import Cipher, ReplayWindow
from matf_vpn.engine import MAX_SEQUENCE_NUMBER
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet
from matf_vpn.transport import Address, UdpTransport
from matf_vpn.tun import TunDevice


SessionKey = Tuple[Address, int]


@dataclass
class ClientSession:
    remote_address: Address
    tunnel_address: ipaddress.IPv4Address
    session_id: int
    cipher: Cipher
    send_sequence: int = 0
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)


class MultiClientServerEngine:
    def __init__(self, tun_device: TunDevice, transport: UdpTransport) -> None:
        self._tun_device = tun_device
        self._transport = transport
        self._sessions: Dict[SessionKey, ClientSession] = {}
        self._routes: Dict[ipaddress.IPv4Address, ClientSession] = {}

    def add_session(self, session: ClientSession) -> None:
        key = (session.remote_address, session.session_id)
        if key in self._sessions:
            raise ValueError("client session already exists")
        if session.tunnel_address in self._routes:
            raise ValueError("client tunnel address already has a session")
        self._sessions[key] = session
        self._routes[session.tunnel_address] = session

    def replace_session(self, session: ClientSession) -> None:
        existing = self._routes.get(session.tunnel_address)
        if existing is not None:
            self.remove_session(existing.remote_address, existing.session_id)
        self.add_session(session)

    def remove_session(self, remote_address: Address, session_id: int) -> None:
        session = self._sessions.pop((remote_address, session_id))
        self._routes.pop(session.tunnel_address, None)

    def run_once(self, timeout: Optional[float] = None) -> int:
        readable, _, _ = select.select(
            [self._tun_device.fileno(), self._transport.fileno()],
            [],
            [],
            timeout,
        )
        forwarded = 0
        if self._tun_device.fileno() in readable and self._forward_tun_packet():
            forwarded += 1
        if self._transport.fileno() in readable and self._forward_udp_packet():
            forwarded += 1
        return forwarded

    def _forward_tun_packet(self) -> bool:
        return self.handle_tun_packet(self._tun_device.read())

    def handle_tun_packet(self, payload: bytes) -> bool:
        try:
            destination = _ipv4_destination(payload)
        except ValueError:
            return False
        session = self._routes.get(destination)
        if session is None:
            return False
        if session.send_sequence > MAX_SEQUENCE_NUMBER:
            raise OverflowError("VPN packet sequence number exhausted")

        packet = Packet(
            MessageType.DATA,
            session.session_id,
            session.send_sequence,
            payload,
        )
        self._transport.send(
            session.cipher.encrypt(packet),
            session.remote_address,
        )
        session.send_sequence += 1
        return True

    def _forward_udp_packet(self) -> bool:
        try:
            packet, remote_address = self._transport.receive()
        except InvalidPacketError:
            return False
        return self.handle_udp_packet(packet, remote_address)

    def handle_udp_packet(self, packet: Packet, remote_address: Address) -> bool:
        session = self._sessions.get((remote_address, packet.session_id))
        if session is None or packet.message_type is not MessageType.DATA:
            return False
        if session.replay_window.is_replay(packet.sequence_number):
            return False
        try:
            decrypted = session.cipher.decrypt(packet)
        except InvalidTag:
            return False
        try:
            source = _ipv4_source(decrypted.payload)
        except ValueError:
            return False
        if source != session.tunnel_address:
            return False

        session.replay_window.mark_authenticated(packet.sequence_number)
        written = self._tun_device.write(decrypted.payload)
        if written != len(decrypted.payload):
            raise OSError("incomplete TUN packet write")
        return True


def _ipv4_source(packet: bytes) -> ipaddress.IPv4Address:
    _validate_ipv4_packet(packet)
    return ipaddress.IPv4Address(packet[12:16])


def _ipv4_destination(packet: bytes) -> ipaddress.IPv4Address:
    _validate_ipv4_packet(packet)
    return ipaddress.IPv4Address(packet[16:20])


def _validate_ipv4_packet(packet: bytes) -> None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError("expected an IPv4 packet")
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or len(packet) < header_length:
        raise ValueError("invalid IPv4 header length")
