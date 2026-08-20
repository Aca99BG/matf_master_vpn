"""X25519 static key agreement for VPN peers."""

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


X25519_KEY_SIZE = 32


def generate_keypair() -> Tuple[bytes, bytes]:
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    if len(private_key) != X25519_KEY_SIZE:
        raise ValueError("X25519 private key must contain 32 bytes")
    if len(peer_public_key) != X25519_KEY_SIZE:
        raise ValueError("X25519 public key must contain 32 bytes")

    return X25519PrivateKey.from_private_bytes(private_key).exchange(
        X25519PublicKey.from_public_bytes(peer_public_key)
    )


def write_keypair(private_path: Path, public_path: Path) -> None:
    private_key, public_key = generate_keypair()
    private_descriptor = os.open(
        str(private_path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(private_descriptor, "w", encoding="ascii") as private_file:
            private_file.write(private_key.hex() + "\n")
        public_descriptor = os.open(
            str(public_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
        with os.fdopen(public_descriptor, "w", encoding="ascii") as public_file:
            public_file.write(public_key.hex() + "\n")
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise
