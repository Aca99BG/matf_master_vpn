"""Authenticated ephemeral X25519 session handshake."""

from dataclasses import dataclass
import hashlib
import hmac
import secrets
import socket
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from matf_vpn.crypto import Cipher, EndpointRole, create_cipher
from matf_vpn.key_agreement import derive_shared_secret, generate_keypair
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet
from matf_vpn.transport import Address, UdpTransport


RANDOM_SIZE = 32
AUTHENTICATION_TAG_SIZE = 32
HELLO_PAYLOAD_SIZE = 32 + RANDOM_SIZE + AUTHENTICATION_TAG_SIZE
HANDSHAKE_CONTEXT = b"matf-vpn-v1 authenticated ephemeral handshake"
DEFAULT_HANDSHAKE_ATTEMPTS = 3


@dataclass(frozen=True)
class ClientHandshakeState:
    session_id: int
    static_private_key: bytes
    peer_static_public_key: bytes
    ephemeral_private_key: bytes
    client_hello_payload: bytes


def run_client_handshake(
    transport: UdpTransport,
    remote_address: Address,
    static_private_key: bytes,
    peer_static_public_key: bytes,
    attempts: int = DEFAULT_HANDSHAKE_ATTEMPTS,
    packets_per_key: int = 0,
) -> Tuple[int, Cipher]:
    hello, state = create_client_hello(static_private_key, peer_static_public_key)
    for _ in range(attempts):
        transport.send(hello, remote_address)
        try:
            response, sender = transport.receive()
        except (socket.timeout, InvalidPacketError):
            continue
        if sender != remote_address:
            continue
        try:
            session_secret = finish_client_handshake(state, response)
        except ValueError:
            continue
        return state.session_id, create_cipher(
            session_secret,
            state.session_id,
            EndpointRole.CLIENT,
            packets_per_key,
        )
    raise TimeoutError("authenticated server handshake timed out")


def run_server_handshake(
    transport: UdpTransport,
    remote_address: Address,
    static_private_key: bytes,
    peer_static_public_key: bytes,
    attempts: int = DEFAULT_HANDSHAKE_ATTEMPTS,
    packets_per_key: int = 0,
) -> Tuple[int, Cipher]:
    for _ in range(attempts):
        try:
            hello, sender = transport.receive()
        except (socket.timeout, InvalidPacketError):
            continue
        if sender != remote_address:
            continue
        try:
            response, session_secret = accept_client_hello(
                hello,
                static_private_key,
                peer_static_public_key,
            )
        except ValueError:
            continue
        transport.send(response, remote_address)
        return hello.session_id, create_cipher(
            session_secret,
            hello.session_id,
            EndpointRole.SERVER,
            packets_per_key,
        )
    raise TimeoutError("authenticated client handshake timed out")


def create_client_hello(
    static_private_key: bytes,
    peer_static_public_key: bytes,
) -> Tuple[Packet, ClientHandshakeState]:
    session_id = secrets.randbits(32)
    ephemeral_private, ephemeral_public = generate_keypair()
    client_random = secrets.token_bytes(RANDOM_SIZE)
    body = ephemeral_public + client_random
    static_secret = derive_shared_secret(static_private_key, peer_static_public_key)
    tag = _authentication_tag(
        static_secret,
        b"client" + session_id.to_bytes(4, "big") + body,
    )
    payload = body + tag
    packet = Packet(MessageType.CLIENT_HELLO, session_id, 0, payload)
    state = ClientHandshakeState(
        session_id,
        static_private_key,
        peer_static_public_key,
        ephemeral_private,
        payload,
    )
    return packet, state


def accept_client_hello(
    packet: Packet,
    static_private_key: bytes,
    peer_static_public_key: bytes,
) -> Tuple[Packet, bytes]:
    _validate_hello(packet, MessageType.CLIENT_HELLO)
    client_ephemeral_public = packet.payload[:32]
    client_body = packet.payload[:-AUTHENTICATION_TAG_SIZE]
    client_tag = packet.payload[-AUTHENTICATION_TAG_SIZE:]
    static_secret = derive_shared_secret(static_private_key, peer_static_public_key)
    expected_tag = _authentication_tag(
        static_secret,
        b"client" + packet.session_id.to_bytes(4, "big") + client_body,
    )
    if not hmac.compare_digest(client_tag, expected_tag):
        raise ValueError("client handshake authentication failed")

    ephemeral_private, ephemeral_public = generate_keypair()
    server_random = secrets.token_bytes(RANDOM_SIZE)
    server_body = ephemeral_public + server_random
    server_tag = _authentication_tag(
        static_secret,
        b"server"
        + packet.session_id.to_bytes(4, "big")
        + packet.payload
        + server_body,
    )
    response = Packet(
        MessageType.SERVER_HELLO,
        packet.session_id,
        0,
        server_body + server_tag,
    )
    session_secret = _derive_session_secret(
        ephemeral_private,
        client_ephemeral_public,
        static_private_key,
        peer_static_public_key,
        packet.payload,
        response.payload,
        local_is_client=False,
    )
    return response, session_secret


def finish_client_handshake(
    state: ClientHandshakeState,
    response: Packet,
) -> bytes:
    _validate_hello(response, MessageType.SERVER_HELLO)
    if response.session_id != state.session_id:
        raise ValueError("server handshake session does not match")

    server_body = response.payload[:-AUTHENTICATION_TAG_SIZE]
    server_tag = response.payload[-AUTHENTICATION_TAG_SIZE:]
    static_secret = derive_shared_secret(
        state.static_private_key,
        state.peer_static_public_key,
    )
    expected_tag = _authentication_tag(
        static_secret,
        b"server"
        + state.session_id.to_bytes(4, "big")
        + state.client_hello_payload
        + server_body,
    )
    if not hmac.compare_digest(server_tag, expected_tag):
        raise ValueError("server handshake authentication failed")

    server_ephemeral_public = response.payload[:32]
    return _derive_session_secret(
        state.ephemeral_private_key,
        server_ephemeral_public,
        state.static_private_key,
        state.peer_static_public_key,
        state.client_hello_payload,
        response.payload,
        local_is_client=True,
    )


def _validate_hello(packet: Packet, expected_type: MessageType) -> None:
    if packet.message_type is not expected_type:
        raise ValueError(f"expected {expected_type.name} packet")
    if packet.sequence_number != 0 or len(packet.payload) != HELLO_PAYLOAD_SIZE:
        raise ValueError("invalid handshake packet")


def _authentication_tag(key: bytes, transcript: bytes) -> bytes:
    return hmac.new(key, HANDSHAKE_CONTEXT + transcript, hashlib.sha256).digest()


def _derive_session_secret(
    ephemeral_private_key: bytes,
    peer_ephemeral_public_key: bytes,
    static_private_key: bytes,
    peer_static_public_key: bytes,
    client_hello_payload: bytes,
    server_hello_payload: bytes,
    local_is_client: bool,
) -> bytes:
    ephemeral_ephemeral = derive_shared_secret(
        ephemeral_private_key,
        peer_ephemeral_public_key,
    )
    if local_is_client:
        ephemeral_static = derive_shared_secret(
            ephemeral_private_key,
            peer_static_public_key,
        )
        static_ephemeral = derive_shared_secret(
            static_private_key,
            peer_ephemeral_public_key,
        )
    else:
        ephemeral_static = derive_shared_secret(
            static_private_key,
            peer_ephemeral_public_key,
        )
        static_ephemeral = derive_shared_secret(
            ephemeral_private_key,
            peer_static_public_key,
        )
    static_static = derive_shared_secret(static_private_key, peer_static_public_key)
    transcript_hash = hashlib.sha256(
        client_hello_payload + server_hello_payload
    ).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=HANDSHAKE_CONTEXT,
        backend=default_backend(),
    ).derive(
        ephemeral_ephemeral
        + ephemeral_static
        + static_ephemeral
        + static_static
    )
