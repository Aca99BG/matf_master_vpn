"""UDP transport for encoded VPN packets."""

import socket
from typing import Optional, Tuple

from matf_vpn.protocol import HEADER, MAX_PAYLOAD_SIZE, Packet


Address = Tuple[str, int]


class UdpTransport:
    def __init__(
        self,
        local_address: Address = ("0.0.0.0", 0),
        timeout: Optional[float] = None,
    ) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(local_address)
        self._socket.settimeout(timeout)

    @property
    def local_address(self) -> Address:
        host, port = self._socket.getsockname()
        return host, port

    def send(self, packet: Packet, remote_address: Address) -> None:
        self._socket.sendto(packet.encode(), remote_address)

    def receive(self) -> Tuple[Packet, Address]:
        data, remote_address = self._socket.recvfrom(HEADER.size + MAX_PAYLOAD_SIZE)
        return Packet.decode(data), remote_address

    def fileno(self) -> int:
        return self._socket.fileno()

    def set_timeout(self, timeout: Optional[float]) -> None:
        self._socket.settimeout(timeout)

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> "UdpTransport":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
