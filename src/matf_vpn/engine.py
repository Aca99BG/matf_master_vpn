"""Bidirectional forwarding between a TUN device and UDP transport."""

import select
import time
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag

from matf_vpn.crypto import Cipher, ReplayWindow
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet
from matf_vpn.transport import Address, UdpTransport
from matf_vpn.tun import TunDevice


MAX_SEQUENCE_NUMBER = 0xFFFFFFFFFFFFFFFF


class TunnelEngine:
    def __init__(
        self,
        tun_device: TunDevice,
        transport: UdpTransport,
        remote_address: Address,
        session_id: int,
        cipher: Optional[Cipher] = None,
        keepalive_interval: float = 0,
        liveness_timeout: float = 0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 <= session_id <= 0xFFFFFFFF:
            raise ValueError("session_id must fit in 32 bits")
        if keepalive_interval < 0 or liveness_timeout < 0:
            raise ValueError("liveness values must not be negative")
        if bool(keepalive_interval) != bool(liveness_timeout):
            raise ValueError("keepalive interval and liveness timeout must be enabled together")
        if liveness_timeout and liveness_timeout <= keepalive_interval:
            raise ValueError("liveness timeout must be greater than keepalive interval")

        self._tun_device = tun_device
        self._transport = transport
        self._remote_address = remote_address
        self._session_id = session_id
        self._sequence_number = 0
        self._cipher = cipher
        self._replay_window = ReplayWindow()
        self._keepalive_interval = keepalive_interval
        self._liveness_timeout = liveness_timeout
        self._clock = clock
        now = clock()
        self._last_authenticated_receive = now
        self._next_keepalive = now + keepalive_interval

    def run(self) -> None:
        while True:
            self.run_once()

    def run_once(self, timeout: Optional[float] = None) -> int:
        tun_descriptor = self._tun_device.fileno()
        transport_descriptor = self._transport.fileno()
        timeout = self._select_timeout(timeout)
        readable, _, _ = select.select(
            [tun_descriptor, transport_descriptor],
            [],
            [],
            timeout,
        )

        forwarded = 0
        if tun_descriptor in readable:
            self._send_tun_packet()
            forwarded += 1
        if transport_descriptor in readable and self._receive_udp_packet():
            forwarded += 1
        if self._keepalive_interval:
            now = self._clock()
            if now >= self._next_keepalive:
                self._send_packet(MessageType.KEEPALIVE, b"")
                self._next_keepalive = now + self._keepalive_interval
            if now - self._last_authenticated_receive >= self._liveness_timeout:
                raise TimeoutError("VPN peer liveness timeout")
        return forwarded

    def _send_tun_packet(self) -> None:
        self._send_packet(MessageType.DATA, self._tun_device.read())

    def _send_packet(self, message_type: MessageType, payload: bytes) -> None:
        if self._sequence_number > MAX_SEQUENCE_NUMBER:
            raise OverflowError("VPN packet sequence number exhausted")

        packet = Packet(
            message_type,
            self._session_id,
            self._sequence_number,
            payload,
        )
        if self._cipher is not None:
            packet = self._cipher.encrypt(packet)
        self._transport.send(packet, self._remote_address)
        self._sequence_number += 1

    def _receive_udp_packet(self) -> bool:
        try:
            packet, remote_address = self._transport.receive()
        except InvalidPacketError:
            return False
        if remote_address != self._remote_address:
            return False
        if packet.session_id != self._session_id:
            return False
        if packet.message_type not in (MessageType.DATA, MessageType.KEEPALIVE):
            return False

        if self._cipher is not None:
            if self._replay_window.is_replay(packet.sequence_number):
                return False
            try:
                packet = self._cipher.decrypt(packet)
            except InvalidTag:
                return False
            self._replay_window.mark_authenticated(packet.sequence_number)
            self._last_authenticated_receive = self._clock()

        if packet.message_type is MessageType.KEEPALIVE:
            return False

        written = self._tun_device.write(packet.payload)
        if written != len(packet.payload):
            raise OSError("incomplete TUN packet write")
        return True

    def _select_timeout(self, requested_timeout: Optional[float]) -> Optional[float]:
        if not self._keepalive_interval:
            return requested_timeout
        now = self._clock()
        internal_timeout = min(
            max(0.0, self._next_keepalive - now),
            max(0.0, self._liveness_timeout - (now - self._last_authenticated_receive)),
        )
        if requested_timeout is None:
            return internal_timeout
        return min(requested_timeout, internal_timeout)
