from concurrent.futures import ThreadPoolExecutor
import unittest

from matf_vpn.handshake import (
    accept_client_hello,
    create_client_hello,
    finish_client_handshake,
    run_client_handshake,
    run_server_handshake,
)
from matf_vpn.key_agreement import generate_keypair
from matf_vpn.protocol import MessageType, Packet
from matf_vpn.transport import UdpTransport


class EphemeralHandshakeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client_private, self.client_public = generate_keypair()
        self.server_private, self.server_public = generate_keypair()

    def test_peers_derive_same_fresh_session_secret(self) -> None:
        hello, state = create_client_hello(self.client_private, self.server_public)
        response, server_secret = accept_client_hello(
            hello,
            self.server_private,
            self.client_public,
        )

        client_secret = finish_client_handshake(state, response)

        self.assertEqual(client_secret, server_secret)
        self.assertEqual(len(client_secret), 32)

    def test_each_handshake_derives_different_secret(self) -> None:
        secrets_derived = []
        for _ in range(2):
            hello, state = create_client_hello(self.client_private, self.server_public)
            response, _ = accept_client_hello(
                hello,
                self.server_private,
                self.client_public,
            )
            secrets_derived.append(finish_client_handshake(state, response))

        self.assertNotEqual(secrets_derived[0], secrets_derived[1])

    def test_rejects_modified_client_hello(self) -> None:
        hello, _ = create_client_hello(self.client_private, self.server_public)
        modified = Packet(
            hello.message_type,
            hello.session_id,
            hello.sequence_number,
            bytes([hello.payload[0] ^ 1]) + hello.payload[1:],
        )

        with self.assertRaisesRegex(ValueError, "client handshake authentication"):
            accept_client_hello(
                modified,
                self.server_private,
                self.client_public,
            )

    def test_rejects_modified_server_hello(self) -> None:
        hello, state = create_client_hello(self.client_private, self.server_public)
        response, _ = accept_client_hello(
            hello,
            self.server_private,
            self.client_public,
        )
        modified = Packet(
            response.message_type,
            response.session_id,
            response.sequence_number,
            response.payload[:-1] + bytes([response.payload[-1] ^ 1]),
        )

        with self.assertRaisesRegex(ValueError, "server handshake authentication"):
            finish_client_handshake(state, modified)

    def test_udp_peers_create_interoperable_session_ciphers(self) -> None:
        with UdpTransport(("127.0.0.1", 0), timeout=1.0) as client_transport:
            with UdpTransport(("127.0.0.1", 0), timeout=1.0) as server_transport:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    server_future = executor.submit(
                        run_server_handshake,
                        server_transport,
                        client_transport.local_address,
                        self.server_private,
                        self.client_public,
                        3,
                        2,
                    )
                    client_session, client_cipher = run_client_handshake(
                        client_transport,
                        server_transport.local_address,
                        self.client_private,
                        self.server_public,
                        packets_per_key=2,
                    )
                    server_session, server_cipher = server_future.result()

        packet = Packet(MessageType.DATA, client_session, 2, b"IPv4 payload")
        self.assertEqual(client_session, server_session)
        self.assertEqual(server_cipher.decrypt(client_cipher.encrypt(packet)), packet)


if __name__ == "__main__":
    unittest.main()