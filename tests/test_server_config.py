import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from matf_vpn.server_config import load_server_config


class MultiClientServerConfigTest(unittest.TestCase):
    def test_loads_clients_and_relative_keys(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "server.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.8.0.1/24",
                        "bind": "0.0.0.0:51820",
                        "private_key_file": "server.key",
                        "clients": [
                            {
                                "name": "first",
                                "tunnel_address": "10.8.0.2",
                                "public_key_file": "first.pub",
                            },
                            {
                                "name": "second",
                                "tunnel_address": "10.8.0.3",
                                "public_key_file": "second.pub",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            config = load_server_config(path)

            self.assertEqual(len(config.clients), 2)
            self.assertEqual(config.private_key_file, Path(directory) / "server.key")
            self.assertEqual(config.clients[1].public_key_file, Path(directory) / "second.pub")

    def test_rejects_client_outside_tunnel_network(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "server.json"
            path.write_text(
                json.dumps(
                    {
                        "tun_address": "10.8.0.1/24",
                        "bind": "0.0.0.0:51820",
                        "private_key_file": "server.key",
                        "clients": [
                            {
                                "name": "outside",
                                "tunnel_address": "10.9.0.2",
                                "public_key_file": "outside.pub",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "inside the server TUN network"):
                load_server_config(path)


if __name__ == "__main__":
    unittest.main()
