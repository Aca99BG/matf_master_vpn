import unittest

from cryptography.exceptions import InvalidTag

from matf_vpn.crypto import (
    AES_GCM_TAG_SIZE,
    EndpointRole,
    PacketCipher,
    ReplayWindow,
    RotatingPacketCipher,
    create_cipher,
)
from matf_vpn.protocol import MAX_PAYLOAD_SIZE, MessageType, Packet


PRESHARED_KEY = bytes(range(32))


class PacketCipherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = PacketCipher.from_preshared_key(
            PRESHARED_KEY,
            session_id=42,
            role=EndpointRole.CLIENT,
        )
        self.server = PacketCipher.from_preshared_key(
            PRESHARED_KEY,
            session_id=42,
            role=EndpointRole.SERVER,
        )

    def test_encrypts_between_directional_peers(self) -> None:
        packet = Packet(MessageType.DATA, 42, 7, b"IPv4 payload")

        encrypted = self.client.encrypt(packet)

        self.assertNotEqual(encrypted.payload, packet.payload)
        self.assertEqual(self.server.decrypt(encrypted), packet)

    def test_sequence_number_changes_ciphertext(self) -> None:
        first = Packet(MessageType.DATA, 42, 7, b"same payload")
        second = Packet(MessageType.DATA, 42, 8, b"same payload")

        self.assertNotEqual(
            self.client.encrypt(first).payload,
            self.client.encrypt(second).payload,
        )

    def test_rejects_modified_ciphertext(self) -> None:
        encrypted = self.client.encrypt(Packet(MessageType.DATA, 42, 7, b"payload"))
        modified = Packet(
            encrypted.message_type,
            encrypted.session_id,
            encrypted.sequence_number,
            encrypted.payload[:-1] + bytes([encrypted.payload[-1] ^ 1]),
        )

        with self.assertRaises(InvalidTag):
            self.server.decrypt(modified)

    def test_rejects_modified_authenticated_header(self) -> None:
        encrypted = self.client.encrypt(Packet(MessageType.DATA, 42, 7, b"payload"))
        modified = Packet(
            encrypted.message_type,
            encrypted.session_id,
            encrypted.sequence_number + 1,
            encrypted.payload,
        )

        with self.assertRaises(InvalidTag):
            self.server.decrypt(modified)

    def test_cannot_decrypt_packet_in_wrong_direction(self) -> None:
        encrypted = self.client.encrypt(Packet(MessageType.DATA, 42, 7, b"payload"))

        with self.assertRaises(InvalidTag):
            self.client.decrypt(encrypted)

    def test_rejects_short_preshared_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            PacketCipher.from_preshared_key(
                b"short",
                session_id=42,
                role=EndpointRole.CLIENT,
            )

    def test_rejects_plaintext_that_exceeds_encrypted_datagram_limit(self) -> None:
        packet = Packet(
            MessageType.DATA,
            42,
            7,
            bytes(MAX_PAYLOAD_SIZE - AES_GCM_TAG_SIZE + 1),
        )

        with self.assertRaisesRegex(ValueError, "plaintext is too large"):
            self.client.encrypt(packet)


class ReplayWindowTest(unittest.TestCase):
    def test_accepts_out_of_order_sequence_once(self) -> None:
        window = ReplayWindow(size=8)

        window.mark_authenticated(5)
        window.mark_authenticated(3)

        self.assertTrue(window.is_replay(5))
        self.assertTrue(window.is_replay(3))
        self.assertFalse(window.is_replay(4))
        self.assertFalse(window.is_replay(6))

    def test_rejects_sequence_outside_window(self) -> None:
        window = ReplayWindow(size=8)
        window.mark_authenticated(10)

        self.assertTrue(window.is_replay(2))
        self.assertFalse(window.is_replay(3))

    def test_rejects_duplicate_mark(self) -> None:
        window = ReplayWindow()
        window.mark_authenticated(1)

        with self.assertRaisesRegex(ValueError, "duplicated"):
            window.mark_authenticated(1)


class RotatingPacketCipherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RotatingPacketCipher(
            PRESHARED_KEY,
            session_id=42,
            role=EndpointRole.CLIENT,
            packets_per_key=2,
        )
        self.server = RotatingPacketCipher(
            PRESHARED_KEY,
            session_id=42,
            role=EndpointRole.SERVER,
            packets_per_key=2,
        )

    def test_rotates_at_packet_boundary(self) -> None:
        self.assertEqual(self.client.epoch_for(0), 0)
        self.assertEqual(self.client.epoch_for(1), 0)
        self.assertEqual(self.client.epoch_for(2), 1)

    def test_peers_interoperate_across_epochs(self) -> None:
        for sequence_number in (0, 1, 2, 3, 4):
            with self.subTest(sequence_number=sequence_number):
                packet = Packet(
                    MessageType.DATA,
                    42,
                    sequence_number,
                    b"IPv4 payload",
                )
                self.assertEqual(
                    self.server.decrypt(self.client.encrypt(packet)),
                    packet,
                )

    def test_can_decrypt_out_of_order_previous_epoch(self) -> None:
        packets = [
            Packet(MessageType.DATA, 42, sequence, b"payload")
            for sequence in (1, 2)
        ]
        encrypted = [self.client.encrypt(packet) for packet in packets]

        self.assertEqual(self.server.decrypt(encrypted[1]), packets[1])
        self.assertEqual(self.server.decrypt(encrypted[0]), packets[0])

    def test_factory_preserves_non_rotating_mode(self) -> None:
        cipher = create_cipher(
            PRESHARED_KEY,
            session_id=42,
            role=EndpointRole.CLIENT,
            packets_per_key=0,
        )

        self.assertIsInstance(cipher, PacketCipher)


if __name__ == "__main__":
    unittest.main()