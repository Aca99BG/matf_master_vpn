import unittest
from unittest.mock import Mock, patch

from matf_vpn.crypto import EndpointRole, PacketCipher
from matf_vpn.engine import TunnelEngine
from matf_vpn.protocol import InvalidPacketError, MessageType, Packet


class TunnelEngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tun_device = Mock()
        self.tun_device.fileno.return_value = 7
        self.transport = Mock()
        self.transport.fileno.return_value = 8
        self.remote_address = ("127.0.0.1", 51820)
        self.engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
        )

    @patch("matf_vpn.engine.select.select", return_value=([7], [], []))
    def test_forwards_tun_packet_to_udp_with_sequence_number(self, select_mock) -> None:
        self.tun_device.read.side_effect = [b"first", b"second"]

        self.engine.run_once()
        self.engine.run_once()

        self.assertEqual(
            self.transport.send.call_args_list[0].args,
            (Packet(MessageType.DATA, 42, 0, b"first"), self.remote_address),
        )
        self.assertEqual(
            self.transport.send.call_args_list[1].args,
            (Packet(MessageType.DATA, 42, 1, b"second"), self.remote_address),
        )

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_forwards_valid_udp_packet_to_tun(self, select_mock) -> None:
        packet = Packet(MessageType.DATA, 42, 3, b"IPv4 packet")
        self.transport.receive.return_value = packet, self.remote_address
        self.tun_device.write.return_value = len(packet.payload)

        self.assertEqual(self.engine.run_once(), 1)

        self.tun_device.write.assert_called_once_with(b"IPv4 packet")

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_drops_packet_from_unexpected_peer(self, select_mock) -> None:
        packet = Packet(MessageType.DATA, 42, 3, b"IPv4 packet")
        self.transport.receive.return_value = packet, ("127.0.0.2", 51820)

        self.assertEqual(self.engine.run_once(), 0)

        self.tun_device.write.assert_not_called()

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_drops_packet_for_another_session(self, select_mock) -> None:
        packet = Packet(MessageType.DATA, 99, 3, b"IPv4 packet")
        self.transport.receive.return_value = packet, self.remote_address

        self.assertEqual(self.engine.run_once(), 0)

        self.tun_device.write.assert_not_called()

    @patch("matf_vpn.engine.select.select", return_value=([7], [], []))
    def test_encrypts_packet_before_sending(self, select_mock) -> None:
        cipher = PacketCipher.from_preshared_key(
            bytes(range(32)),
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=cipher,
        )
        self.tun_device.read.return_value = b"IPv4 packet"

        engine.run_once()

        sent_packet = self.transport.send.call_args.args[0]
        self.assertNotEqual(sent_packet.payload, b"IPv4 packet")

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_decrypts_authenticated_packet_and_drops_replay(self, select_mock) -> None:
        preshared_key = bytes(range(32))
        client_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        server_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.SERVER,
        )
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=server_cipher,
        )
        encrypted = client_cipher.encrypt(
            Packet(MessageType.DATA, 42, 5, b"IPv4 packet")
        )
        self.transport.receive.return_value = encrypted, self.remote_address
        self.tun_device.write.return_value = len(b"IPv4 packet")

        self.assertEqual(engine.run_once(), 1)
        self.assertEqual(engine.run_once(), 0)

        self.tun_device.write.assert_called_once_with(b"IPv4 packet")

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_authentication_failure_does_not_consume_sequence(self, select_mock) -> None:
        preshared_key = bytes(range(32))
        client_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        server_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.SERVER,
        )
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=server_cipher,
        )
        encrypted = client_cipher.encrypt(
            Packet(MessageType.DATA, 42, 5, b"IPv4 packet")
        )
        forged = Packet(
            encrypted.message_type,
            encrypted.session_id,
            encrypted.sequence_number,
            encrypted.payload[:-1] + bytes([encrypted.payload[-1] ^ 1]),
        )
        self.transport.receive.side_effect = [
            (forged, self.remote_address),
            (encrypted, self.remote_address),
        ]
        self.tun_device.write.return_value = len(b"IPv4 packet")

        self.assertEqual(engine.run_once(), 0)
        self.assertEqual(engine.run_once(), 1)

        self.tun_device.write.assert_called_once_with(b"IPv4 packet")

    @patch("matf_vpn.engine.select.select", return_value=([], [], []))
    def test_sends_encrypted_keepalive_at_interval(self, select_mock) -> None:
        clock = Mock(side_effect=[0.0, 5.0, 5.0])
        cipher = PacketCipher.from_preshared_key(
            bytes(range(32)),
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=cipher,
            keepalive_interval=5.0,
            liveness_timeout=15.0,
            clock=clock,
        )

        engine.run_once()

        sent_packet = self.transport.send.call_args.args[0]
        self.assertEqual(sent_packet.message_type, MessageType.KEEPALIVE)
        self.assertNotEqual(sent_packet.payload, b"")

    @patch("matf_vpn.engine.select.select", return_value=([], [], []))
    def test_raises_when_authenticated_peer_becomes_silent(self, select_mock) -> None:
        clock = Mock(side_effect=[0.0, 11.0, 11.0])
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=Mock(),
            keepalive_interval=5.0,
            liveness_timeout=10.0,
            clock=clock,
        )

        with self.assertRaisesRegex(TimeoutError, "liveness timeout"):
            engine.run_once()

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_authenticated_keepalive_refreshes_liveness(self, select_mock) -> None:
        preshared_key = bytes(range(32))
        client_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        server_cipher = PacketCipher.from_preshared_key(
            preshared_key,
            session_id=42,
            role=EndpointRole.SERVER,
        )
        clock = Mock(side_effect=[0.0, 9.0, 9.0, 9.0])
        engine = TunnelEngine(
            self.tun_device,
            self.transport,
            self.remote_address,
            session_id=42,
            cipher=server_cipher,
            keepalive_interval=5.0,
            liveness_timeout=10.0,
            clock=clock,
        )
        keepalive = client_cipher.encrypt(
            Packet(MessageType.KEEPALIVE, 42, 1, b"")
        )
        self.transport.receive.return_value = keepalive, self.remote_address

        self.assertEqual(engine.run_once(), 0)

        self.tun_device.write.assert_not_called()

    @patch("matf_vpn.engine.select.select", return_value=([8], [], []))
    def test_drops_malformed_udp_datagram(self, select_mock) -> None:
        self.transport.receive.side_effect = InvalidPacketError("malformed")

        self.assertEqual(self.engine.run_once(), 0)


if __name__ == "__main__":
    unittest.main()