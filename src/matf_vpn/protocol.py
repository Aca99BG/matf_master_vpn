"""Binary packet format shared by the VPN client and server."""

from dataclasses import dataclass
from enum import IntEnum
import struct


PROTOCOL_VERSION = 1
HEADER = struct.Struct("!BBIQH")
MAX_UDP_DATAGRAM_SIZE = 65_507
MAX_PAYLOAD_SIZE = MAX_UDP_DATAGRAM_SIZE - HEADER.size


class InvalidPacketError(ValueError):
    pass


class MessageType(IntEnum):
    DATA = 1
    KEEPALIVE = 2
    CLIENT_HELLO = 3
    SERVER_HELLO = 4


@dataclass(frozen=True)
class Packet:
    message_type: MessageType
    session_id: int
    sequence_number: int
    payload: bytes = b""

    def encode(self) -> bytes:
        if not 0 <= self.session_id <= 0xFFFFFFFF:
            raise ValueError("session_id must fit in 32 bits")
        if not 0 <= self.sequence_number <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("sequence_number must fit in 64 bits")
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("payload is too large")

        return HEADER.pack(
            PROTOCOL_VERSION,
            self.message_type,
            self.session_id,
            self.sequence_number,
            len(self.payload),
        ) + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "Packet":
        if len(data) < HEADER.size:
            raise InvalidPacketError("packet is shorter than the header")

        version, raw_type, session_id, sequence_number, payload_size = HEADER.unpack_from(data)
        if version != PROTOCOL_VERSION:
            raise InvalidPacketError(f"unsupported protocol version: {version}")
        if len(data) != HEADER.size + payload_size:
            raise InvalidPacketError("payload length does not match the header")

        try:
            message_type = MessageType(raw_type)
        except ValueError as error:
            raise InvalidPacketError(f"unsupported message type: {raw_type}") from error

        return cls(message_type, session_id, sequence_number, data[HEADER.size:])
