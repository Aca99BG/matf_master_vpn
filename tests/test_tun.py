import os
import struct
import unittest
from unittest.mock import patch

from matf_vpn.tun import IFF_NO_PI, IFF_TUN, TUNSETIFF, TunDevice


class TunDeviceTest(unittest.TestCase):
    @patch("matf_vpn.tun.os.close")
    @patch("matf_vpn.tun.os.write", return_value=10)
    @patch("matf_vpn.tun.os.read", return_value=b"IPv4 packet")
    @patch("matf_vpn.tun.fcntl.ioctl", return_value=struct.pack("16sH", b"mvpn0", 0))
    @patch("matf_vpn.tun.os.open", return_value=7)
    def test_reads_and_writes_packets(
        self,
        open_mock,
        ioctl_mock,
        read_mock,
        write_mock,
        close_mock,
    ) -> None:
        with TunDevice("mvpn%d") as device:
            self.assertEqual(device.name, "mvpn0")
            self.assertEqual(device.fileno(), 7)
            self.assertEqual(device.read(), b"IPv4 packet")
            self.assertEqual(device.write(b"IP payload"), 10)

        open_mock.assert_called_once_with("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        request = ioctl_mock.call_args.args[2]
        self.assertEqual(struct.unpack("16sH", request)[1], IFF_TUN | IFF_NO_PI)
        read_mock.assert_called_once_with(7, 65_535)
        write_mock.assert_called_once_with(7, b"IP payload")
        close_mock.assert_called_once_with(7)

    @patch("matf_vpn.tun.os.close")
    @patch("matf_vpn.tun.fcntl.ioctl", side_effect=OSError("ioctl failed"))
    @patch("matf_vpn.tun.os.open", return_value=7)
    def test_closes_descriptor_when_configuration_fails(
        self,
        open_mock,
        ioctl_mock,
        close_mock,
    ) -> None:
        with self.assertRaisesRegex(OSError, "ioctl failed"):
            TunDevice("mvpn0")

        close_mock.assert_called_once_with(7)

    def test_rejects_invalid_interface_name(self) -> None:
        for name in ("", "interface-name-too-long", "tun\N{SNOWMAN}"):
            with self.subTest(name=name):
                with self.assertRaises((UnicodeEncodeError, ValueError)):
                    TunDevice(name)


if __name__ == "__main__":
    unittest.main()