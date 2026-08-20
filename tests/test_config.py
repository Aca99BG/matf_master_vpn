import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.config import load_config
from matf_vpn.crypto import EndpointRole


class EndpointConfigTest(unittest.TestCase):
    def test_loads_ephemeral_profile_and_resolves_relative_paths(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "client.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                        "private_key_file": "client.key",
                        "peer_public_key_file": "server.pub",
                        "role": "client",
                        "ephemeral_handshake": True,
                        "packets_per_key": 1000,
                        "keepalive_interval": 5.0,
                        "liveness_timeout": 15.0,
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(path)

            self.assertEqual(config.tun_name, "mvpn0")
            self.assertEqual(config.bind, ("192.0.2.1", 51820))
            self.assertEqual(config.private_key_file, Path(directory) / "client.key")
            self.assertEqual(config.role, EndpointRole.CLIENT)
            self.assertTrue(config.ephemeral_handshake)
            self.assertEqual(config.liveness_timeout, 15.0)

    def test_rejects_unknown_field(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                        "typo": True,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unknown configuration fields: typo"):
                load_config(path)

    def test_rejects_invalid_security_combination(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                        "ephemeral_handshake": True,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "requires X25519"):
                load_config(path)

    def test_rejects_liveness_without_ephemeral_handshake(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.1/30",
                        "bind": "192.0.2.1:51820",
                        "peer": "192.0.2.2:51820",
                        "keepalive_interval": 5.0,
                        "liveness_timeout": 15.0,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "active liveness"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()