"""Authenticated encryption for VPN packet payloads."""

from collections import OrderedDict
from enum import Enum
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from matf_vpn.protocol import HEADER, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION, Packet


AES_KEY_SIZE = 32
AES_GCM_TAG_SIZE = 16
MINIMUM_PRESHARED_KEY_SIZE = 32
KEY_DERIVATION_CONTEXT = b"matf-vpn-v1 directional keys"
KEY_ROTATION_CONTEXT = b"matf-vpn-v1 packet-count key rotation"
DEFAULT_REPLAY_WINDOW_SIZE = 64
ROTATION_CIPHER_CACHE_SIZE = 2


class EndpointRole(Enum):
    CLIENT = "client"
    SERVER = "server"


class ReplayWindow:
    def __init__(self, size: int = DEFAULT_REPLAY_WINDOW_SIZE) -> None:
        if size <= 0:
            raise ValueError("replay window size must be positive")
        self._size = size
        self._highest_sequence = -1
        self._bitmap = 0

    def is_replay(self, sequence_number: int) -> bool:
        if sequence_number < 0:
            return True
        if sequence_number > self._highest_sequence:
            return False

        distance = self._highest_sequence - sequence_number
        if distance >= self._size:
            return True
        return bool(self._bitmap & (1 << distance))

    def mark_authenticated(self, sequence_number: int) -> None:
        if self.is_replay(sequence_number):
            raise ValueError("sequence number is duplicated or outside the replay window")

        if sequence_number > self._highest_sequence:
            shift = sequence_number - self._highest_sequence
            if shift >= self._size:
                self._bitmap = 0
            else:
                self._bitmap <<= shift
                self._bitmap &= (1 << self._size) - 1
            self._highest_sequence = sequence_number
            self._bitmap |= 1
            return

        distance = self._highest_sequence - sequence_number
        self._bitmap |= 1 << distance


class PacketCipher:
    def __init__(self, send_key: bytes, receive_key: bytes) -> None:
        if len(send_key) != AES_KEY_SIZE or len(receive_key) != AES_KEY_SIZE:
            raise ValueError("AES-256-GCM keys must contain 32 bytes")
        self._send_cipher = AESGCM(send_key)
        self._receive_cipher = AESGCM(receive_key)

    @classmethod
    def from_preshared_key(
        cls,
        preshared_key: bytes,
        session_id: int,
        role: EndpointRole,
    ) -> "PacketCipher":
        if len(preshared_key) < MINIMUM_PRESHARED_KEY_SIZE:
            raise ValueError("preshared key must contain at least 32 bytes")
        if not 0 <= session_id <= 0xFFFFFFFF:
            raise ValueError("session_id must fit in 32 bits")

        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=2 * AES_KEY_SIZE,
            salt=session_id.to_bytes(4, "big"),
            info=KEY_DERIVATION_CONTEXT,
            backend=default_backend(),
        ).derive(preshared_key)
        client_to_server = key_material[:AES_KEY_SIZE]
        server_to_client = key_material[AES_KEY_SIZE:]

        if role is EndpointRole.CLIENT:
            return cls(client_to_server, server_to_client)
        if role is EndpointRole.SERVER:
            return cls(server_to_client, client_to_server)
        raise ValueError("unsupported endpoint role")

    def encrypt(self, packet: Packet) -> Packet:
        if len(packet.payload) > MAX_PAYLOAD_SIZE - AES_GCM_TAG_SIZE:
            raise ValueError("plaintext is too large for an encrypted UDP packet")
        encrypted_size = len(packet.payload) + AES_GCM_TAG_SIZE
        ciphertext = self._send_cipher.encrypt(
            _nonce(packet),
            packet.payload,
            _authenticated_header(packet, encrypted_size),
        )
        return Packet(
            packet.message_type,
            packet.session_id,
            packet.sequence_number,
            ciphertext,
        )

    def decrypt(self, packet: Packet) -> Packet:
        plaintext = self._receive_cipher.decrypt(
            _nonce(packet),
            packet.payload,
            _authenticated_header(packet, len(packet.payload)),
        )
        return Packet(
            packet.message_type,
            packet.session_id,
            packet.sequence_number,
            plaintext,
        )


class RotatingPacketCipher:
    def __init__(
        self,
        master_secret: bytes,
        session_id: int,
        role: EndpointRole,
        packets_per_key: int,
    ) -> None:
        if len(master_secret) < MINIMUM_PRESHARED_KEY_SIZE:
            raise ValueError("master secret must contain at least 32 bytes")
        if not 0 <= session_id <= 0xFFFFFFFF:
            raise ValueError("session_id must fit in 32 bits")
        if packets_per_key <= 0:
            raise ValueError("packets_per_key must be positive")
        self._master_secret = master_secret
        self._session_id = session_id
        self._role = role
        self._packets_per_key = packets_per_key
        self._ciphers: "OrderedDict[int, PacketCipher]" = OrderedDict()

    def encrypt(self, packet: Packet) -> Packet:
        return self._cipher_for(packet.sequence_number).encrypt(packet)

    def decrypt(self, packet: Packet) -> Packet:
        return self._cipher_for(packet.sequence_number).decrypt(packet)

    def epoch_for(self, sequence_number: int) -> int:
        if sequence_number < 0:
            raise ValueError("sequence_number must not be negative")
        return sequence_number // self._packets_per_key

    def _cipher_for(self, sequence_number: int) -> PacketCipher:
        epoch = self.epoch_for(sequence_number)
        cipher = self._ciphers.get(epoch)
        if cipher is not None:
            self._ciphers.move_to_end(epoch)
            return cipher

        epoch_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._session_id.to_bytes(4, "big") + epoch.to_bytes(8, "big"),
            info=KEY_ROTATION_CONTEXT,
            backend=default_backend(),
        ).derive(self._master_secret)
        cipher = PacketCipher.from_preshared_key(
            epoch_secret,
            self._session_id,
            self._role,
        )
        self._ciphers[epoch] = cipher
        if len(self._ciphers) > ROTATION_CIPHER_CACHE_SIZE:
            self._ciphers.popitem(last=False)
        return cipher


Cipher = Union[PacketCipher, RotatingPacketCipher]


def create_cipher(
    master_secret: bytes,
    session_id: int,
    role: EndpointRole,
    packets_per_key: int = 0,
) -> Cipher:
    if packets_per_key < 0:
        raise ValueError("packets_per_key must not be negative")
    if packets_per_key == 0:
        return PacketCipher.from_preshared_key(master_secret, session_id, role)
    return RotatingPacketCipher(master_secret, session_id, role, packets_per_key)


def _nonce(packet: Packet) -> bytes:
    return packet.session_id.to_bytes(4, "big") + packet.sequence_number.to_bytes(8, "big")


def _authenticated_header(packet: Packet, payload_size: int) -> bytes:
    return HEADER.pack(
        PROTOCOL_VERSION,
        packet.message_type,
        packet.session_id,
        packet.sequence_number,
        payload_size,
    )
