import unittest

from matf_vpn.protocol import MAX_PAYLOAD_SIZE, MessageType, Packet


class PacketTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        packet = Packet(MessageType.DATA, 42, 7, b"IP packet")

        self.assertEqual(Packet.decode(packet.encode()), packet)

    def test_rejects_unsupported_version(self) -> None:
        encoded = bytearray(Packet(MessageType.KEEPALIVE, 42, 8).encode())
        encoded[0] = 2

        with self.assertRaisesRegex(ValueError, "unsupported protocol version"):
            Packet.decode(encoded)

    def test_rejects_incorrect_payload_length(self) -> None:
        encoded = Packet(MessageType.DATA, 42, 9, b"payload").encode()

        with self.assertRaisesRegex(ValueError, "payload length"):
            Packet.decode(encoded[:-1])

    def test_rejects_payload_larger_than_udp_datagram_limit(self) -> None:
        packet = Packet(MessageType.DATA, 42, 10, bytes(MAX_PAYLOAD_SIZE + 1))

        with self.assertRaisesRegex(ValueError, "payload is too large"):
            packet.encode()


if __name__ == "__main__":
    unittest.main()