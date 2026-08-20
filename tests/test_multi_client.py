import ipaddress
import unittest
from unittest.mock import Mock, patch

from matf_vpn.crypto import EndpointRole, PacketCipher
from matf_vpn.multi_client import ClientSession, MultiClientServerEngine
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet


def ipv4_packet(source: str, destination: str, payload: bytes = b"") -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    total_length = 20 + len(payload)
    header[2:4] = total_length.to_bytes(2, "big")
    header[8] = 64
    header[9] = 1
    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed
    return bytes(header) + payload


class MultiClientServerEngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tun_device = Mock()
        self.tun_device.fileno.return_value = 7
        self.transport = Mock()
        self.transport.fileno.return_value = 8
        self.engine = MultiClientServerEngine(self.tun_device, self.transport)
        self.secret = bytes(range(32))

    def add_client(self, host: str, port: int, tunnel_address: str, session_id: int):
        server_cipher = PacketCipher.from_preshared_key(
            self.secret,
            session_id,
            EndpointRole.SERVER,
        )
        session = ClientSession(
            (host, port),
            ipaddress.IPv4Address(tunnel_address),
            session_id,
            server_cipher,
        )
        self.engine.add_session(session)
        return session

    @patch("matf_vpn.multi_client.select.select", return_value=([7], [], []))
    def test_routes_tun_packet_to_client_by_destination(self, select_mock) -> None:
        first = self.add_client("192.0.2.10", 5000, "10.8.0.2", 10)
        self.add_client("192.0.2.11", 5001, "10.8.0.3", 11)
        payload = ipv4_packet("10.8.0.1", "10.8.0.2", b"ping")
        self.tun_device.read.return_value = payload

        self.assertEqual(self.engine.run_once(), 1)

        encrypted, remote_address = self.transport.send.call_args.args
        self.assertEqual(remote_address, first.remote_address)
        client_cipher = PacketCipher.from_preshared_key(
            self.secret,
            10,
            EndpointRole.CLIENT,
        )
        self.assertEqual(client_cipher.decrypt(encrypted).payload, payload)

    @patch("matf_vpn.multi_client.select.select", return_value=([8], [], []))
    def test_accepts_authenticated_packet_from_assigned_client_address(self, select_mock) -> None:
        session = self.add_client("192.0.2.10", 5000, "10.8.0.2", 10)
        client_cipher = PacketCipher.from_preshared_key(
            self.secret,
            10,
            EndpointRole.CLIENT,
        )
        payload = ipv4_packet("10.8.0.2", "10.8.0.1", b"reply")
        encrypted = client_cipher.encrypt(Packet(MessageType.DATA, 10, 0, payload))
        self.transport.receive.return_value = encrypted, session.remote_address
        self.tun_device.write.return_value = len(payload)

        self.assertEqual(self.engine.run_once(), 1)
        self.tun_device.write.assert_called_once_with(payload)

    @patch("matf_vpn.multi_client.select.select", return_value=([8], [], []))
    def test_rejects_client_source_address_spoofing(self, select_mock) -> None:
        session = self.add_client("192.0.2.10", 5000, "10.8.0.2", 10)
        client_cipher = PacketCipher.from_preshared_key(
            self.secret,
            10,
            EndpointRole.CLIENT,
        )
        spoofed = ipv4_packet("10.8.0.3", "10.8.0.1")
        encrypted = client_cipher.encrypt(Packet(MessageType.DATA, 10, 0, spoofed))
        self.transport.receive.return_value = encrypted, session.remote_address

        self.assertEqual(self.engine.run_once(), 0)
        self.tun_device.write.assert_not_called()

    def test_rejects_duplicate_tunnel_address(self) -> None:
        self.add_client("192.0.2.10", 5000, "10.8.0.2", 10)

        with self.assertRaisesRegex(ValueError, "already has a session"):
            self.add_client("192.0.2.11", 5001, "10.8.0.2", 11)

    @patch("matf_vpn.multi_client.select.select", return_value=([7], [], []))
    def test_drops_non_ipv4_tun_packet_without_stopping_server(self, select_mock) -> None:
        self.tun_device.read.return_value = bytes([0x60]) + bytes(39)

        self.assertEqual(self.engine.run_once(), 0)

        self.transport.send.assert_not_called()

    @patch("matf_vpn.multi_client.select.select", return_value=([8], [], []))
    def test_drops_malformed_udp_datagram(self, select_mock) -> None:
        self.transport.receive.side_effect = InvalidPacketError("malformed")

        self.assertEqual(self.engine.run_once(), 0)


if __name__ == "__main__":
    unittest.main()