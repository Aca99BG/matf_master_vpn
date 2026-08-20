import ipaddress
import unittest

from matf_vpn.handshake import create_client_hello, finish_client_handshake
from matf_vpn.key_agreement import generate_keypair
from matf_vpn.multi_server import ClientIdentity, ClientRegistry


class ClientRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server_private, self.server_public = generate_keypair()
        self.first_private, self.first_public = generate_keypair()
        self.second_private, self.second_public = generate_keypair()
        self.registry = ClientRegistry(
            self.server_private,
            [
                ClientIdentity(
                    "first",
                    ipaddress.IPv4Address("10.8.0.2"),
                    self.first_public,
                ),
                ClientIdentity(
                    "second",
                    ipaddress.IPv4Address("10.8.0.3"),
                    self.second_public,
                ),
            ],
            packets_per_key=2,
        )

    def test_accepts_each_registered_client(self) -> None:
        for name, private_key, tunnel_address, port in (
            ("first", self.first_private, "10.8.0.2", 5000),
            ("second", self.second_private, "10.8.0.3", 5001),
        ):
            with self.subTest(client=name):
                hello, state = create_client_hello(private_key, self.server_public)

                accepted = self.registry.accept(hello, ("192.0.2.10", port))

                self.assertIsNotNone(accepted)
                client_secret = finish_client_handshake(state, accepted.response)
                self.assertEqual(accepted.identity.name, name)
                self.assertEqual(
                    accepted.session.tunnel_address,
                    ipaddress.IPv4Address(tunnel_address),
                )
                self.assertTrue(accepted.is_new)
                self.assertEqual(len(client_secret), 32)

    def test_rejects_unregistered_client(self) -> None:
        unknown_private, _ = generate_keypair()
        hello, _ = create_client_hello(unknown_private, self.server_public)

        self.assertIsNone(self.registry.accept(hello, ("192.0.2.99", 5999)))

    def test_replayed_hello_resends_response_without_replacing_session(self) -> None:
        hello, _ = create_client_hello(self.first_private, self.server_public)
        remote_address = ("192.0.2.10", 5000)

        first = self.registry.accept(hello, remote_address)
        replay = self.registry.accept(hello, remote_address)

        self.assertIsNotNone(first)
        self.assertIsNotNone(replay)
        self.assertTrue(first.is_new)
        self.assertFalse(replay.is_new)
        self.assertEqual(replay.response, first.response)
        self.assertIs(replay.session, first.session)

    def test_rejects_duplicate_tunnel_addresses(self) -> None:
        with self.assertRaisesRegex(ValueError, "tunnel addresses must be unique"):
            ClientRegistry(
                self.server_private,
                [
                    ClientIdentity("first", ipaddress.IPv4Address("10.8.0.2"), self.first_public),
                    ClientIdentity("second", ipaddress.IPv4Address("10.8.0.2"), self.second_public),
                ],
            )


if __name__ == "__main__":
    unittest.main()