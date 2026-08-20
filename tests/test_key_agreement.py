from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.key_agreement import derive_shared_secret, generate_keypair, write_keypair


class X25519KeyAgreementTest(unittest.TestCase):
    def test_peers_derive_same_shared_secret(self) -> None:
        client_private, client_public = generate_keypair()
        server_private, server_public = generate_keypair()

        client_secret = derive_shared_secret(client_private, server_public)
        server_secret = derive_shared_secret(server_private, client_public)

        self.assertEqual(client_secret, server_secret)
        self.assertEqual(len(client_secret), 32)

    def test_generated_keypairs_are_distinct(self) -> None:
        first_private, first_public = generate_keypair()
        second_private, second_public = generate_keypair()

        self.assertNotEqual(first_private, second_private)
        self.assertNotEqual(first_public, second_public)

    def test_rejects_invalid_key_lengths(self) -> None:
        private_key, public_key = generate_keypair()

        with self.assertRaisesRegex(ValueError, "private key"):
            derive_shared_secret(private_key[:-1], public_key)
        with self.assertRaisesRegex(ValueError, "public key"):
            derive_shared_secret(private_key, public_key[:-1])

    def test_writes_keypair_with_safe_permissions(self) -> None:
        with TemporaryDirectory() as directory:
            private_path = Path(directory) / "identity.key"
            public_path = Path(directory) / "identity.pub"

            write_keypair(private_path, public_path)

            self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(public_path.stat().st_mode), 0o644)
            self.assertEqual(len(bytes.fromhex(private_path.read_text().strip())), 32)
            self.assertEqual(len(bytes.fromhex(public_path.read_text().strip())), 32)

    def test_does_not_overwrite_existing_private_key(self) -> None:
        with TemporaryDirectory() as directory:
            private_path = Path(directory) / "identity.key"
            public_path = Path(directory) / "identity.pub"
            private_path.write_text("existing", encoding="ascii")

            with self.assertRaises(FileExistsError):
                write_keypair(private_path, public_path)

            self.assertEqual(private_path.read_text(encoding="ascii"), "existing")
            self.assertFalse(public_path.exists())


if __name__ == "__main__":
    unittest.main()