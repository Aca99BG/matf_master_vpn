import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.cli import (
    load_preshared_key,
    load_x25519_key,
    parse_endpoint,
    parse_options,
)


class ParseEndpointTest(unittest.TestCase):
    def test_parses_ipv4_endpoint(self) -> None:
        self.assertEqual(parse_endpoint("127.0.0.1:51820"), ("127.0.0.1", 51820))

    def test_rejects_invalid_endpoint(self) -> None:
        for endpoint in ("localhost:51820", "127.0.0.1", "127.0.0.1:0"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parse_endpoint(endpoint)


class ParseOptionsTest(unittest.TestCase):
    def test_loads_config_profile(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "client.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                    }
                ),
                encoding="utf-8",
            )

            options = parse_options(["--config", str(path)])

            self.assertEqual(options.tun_address, "10.0.0.1/30")
            self.assertEqual(options.bind, ("192.0.2.1", 51820))

    def test_rejects_config_mixed_with_endpoint_options(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "client.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                parse_options(["--config", str(path), "--mtu", "1300"])


class LoadPresharedKeyTest(unittest.TestCase):
    def test_loads_hexadecimal_key(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.key"
            path.write_text(bytes(range(32)).hex(), encoding="ascii")
            path.chmod(0o600)

            self.assertEqual(load_preshared_key(path), bytes(range(32)))

    def test_rejects_short_key(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.key"
            path.write_text("00", encoding="ascii")
            path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
                load_preshared_key(path)


class LoadX25519KeyTest(unittest.TestCase):
    def test_loads_private_and_public_keys(self) -> None:
        with TemporaryDirectory() as directory:
            private_path = Path(directory) / "identity.key"
            public_path = Path(directory) / "peer.pub"
            private_path.write_text(bytes(range(32)).hex(), encoding="ascii")
            private_path.chmod(0o600)
            public_path.write_text(bytes(reversed(range(32))).hex(), encoding="ascii")
            public_path.chmod(0o644)

            self.assertEqual(load_x25519_key(private_path, private=True), bytes(range(32)))
            self.assertEqual(
                load_x25519_key(public_path, private=False),
                bytes(reversed(range(32))),
            )

    def test_rejects_public_key_with_wrong_size(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "peer.pub"
            path.write_text("00", encoding="ascii")

            with self.assertRaisesRegex(ValueError, "32 bytes"):
                load_x25519_key(path, private=False)

    def test_rejects_key_accessible_by_other_users(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.key"
            path.write_text(bytes(range(32)).hex(), encoding="ascii")
            path.chmod(0o644)

            with self.assertRaisesRegex(ValueError, "group or other users"):
                load_preshared_key(path)


if __name__ == "__main__":
    unittest.main()
