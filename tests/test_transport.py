import socket
import unittest

from matf_vpn.protocol import MessageType, Packet
from matf_vpn.transport import UdpTransport


class UdpTransportTest(unittest.TestCase):
    def test_sends_packet_over_loopback(self) -> None:
        packet = Packet(MessageType.DATA, 42, 1, b"IPv4 payload")

        with UdpTransport(("127.0.0.1", 0), timeout=1.0) as server:
            with UdpTransport(("127.0.0.1", 0), timeout=1.0) as client:
                self.assertGreaterEqual(client.fileno(), 0)
                client.send(packet, server.local_address)
                received, remote_address = server.receive()

                self.assertEqual(received, packet)
                self.assertEqual(remote_address, client.local_address)

    def test_receive_honors_timeout(self) -> None:
        with UdpTransport(("127.0.0.1", 0), timeout=0.01) as transport:
            with self.assertRaises(socket.timeout):
                transport.receive()

    def test_can_change_timeout(self) -> None:
        with UdpTransport(("127.0.0.1", 0)) as transport:
            transport.set_timeout(0.01)

            with self.assertRaises(socket.timeout):
                transport.receive()


if __name__ == "__main__":
    unittest.main()