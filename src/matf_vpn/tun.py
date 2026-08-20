"""Linux TUN interface adapter."""

import fcntl
import os
import struct
from typing import Optional, Type


TUN_DEVICE = "/dev/net/tun"
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFNAMSIZ = 16
DEFAULT_PACKET_SIZE = 65_535


class TunDevice:
    def __init__(self, name: str = "mvpn%d") -> None:
        encoded_name = name.encode("ascii")
        if not encoded_name or len(encoded_name) >= IFNAMSIZ or b"\x00" in encoded_name:
            raise ValueError("TUN interface name must contain 1 to 15 ASCII bytes")

        self._file_descriptor: Optional[int] = os.open(
            TUN_DEVICE,
            os.O_RDWR | os.O_CLOEXEC,
        )
        request = struct.pack("16sH", encoded_name, IFF_TUN | IFF_NO_PI)

        try:
            response = fcntl.ioctl(self._file_descriptor, TUNSETIFF, request)
        except BaseException:
            self.close()
            raise

        self._name = response[:IFNAMSIZ].split(b"\x00", 1)[0].decode("ascii")

    @property
    def name(self) -> str:
        return self._name

    def read(self, size: int = DEFAULT_PACKET_SIZE) -> bytes:
        return os.read(self._require_open(), size)

    def write(self, packet: bytes) -> int:
        return os.write(self._require_open(), packet)

    def fileno(self) -> int:
        return self._require_open()

    def close(self) -> None:
        if self._file_descriptor is not None:
            os.close(self._file_descriptor)
            self._file_descriptor = None

    def _require_open(self) -> int:
        if self._file_descriptor is None:
            raise RuntimeError("TUN device is closed")
        return self._file_descriptor

    def __enter__(self) -> "TunDevice":
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]],
        exception: Optional[BaseException],
        traceback: object,
    ) -> None:
        self.close()
