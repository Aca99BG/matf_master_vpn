import unittest
from unittest.mock import call, patch

from matf_vpn.network import configure_tun


class ConfigureTunTest(unittest.TestCase):
    @patch("matf_vpn.network.subprocess.run")
    def test_configures_address_mtu_and_link_state(self, run_mock) -> None:
        configure_tun("mvpn0", "10.0.0.1/30", 1400)

        self.assertEqual(
            run_mock.call_args_list,
            [
                call(
                    ["ip", "address", "add", "10.0.0.1/30", "dev", "mvpn0"],
                    check=True,
                ),
                call(
                    ["ip", "link", "set", "dev", "mvpn0", "mtu", "1400", "up"],
                    check=True,
                ),
            ],
        )

    def test_rejects_invalid_mtu(self) -> None:
        with self.assertRaisesRegex(ValueError, "MTU"):
            configure_tun("mvpn0", "10.0.0.1/30", 500)


if __name__ == "__main__":
    unittest.main()
