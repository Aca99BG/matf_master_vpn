import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

from matf_vpn.gui import EndpointProcess, MainWindow, validate_profile_keys
from matf_vpn.config import load_config


APPLICATION = QApplication.instance() or QApplication([])


class EndpointProcessTest(unittest.TestCase):
    def test_updates_state_from_structured_events(self) -> None:
        controller = EndpointProcess()

        controller.consume_log_line(json.dumps({"event": "session_established"}))
        self.assertEqual(controller.state, "connected")

        controller.consume_log_line(json.dumps({"event": "reconnect_scheduled"}))
        self.assertEqual(controller.state, "reconnecting")

    def test_reports_non_json_process_output(self) -> None:
        controller = EndpointProcess()
        errors = []
        controller.error_received.connect(errors.append)

        controller.consume_log_line("authentication cancelled")

        self.assertEqual(errors, ["authentication cancelled"])

    def test_preflight_reports_missing_key_before_process_start(self) -> None:
        with TemporaryDirectory() as directory:
            profile = Path(directory) / "client.json"
            profile.write_text(
                json.dumps(
                    {
                        "tun_address": "10.8.0.2/24",
                        "bind": "0.0.0.0:51820",
                        "peer": "192.0.2.2:51820",
                        "private_key_file": "missing-client.key",
                        "peer_public_key_file": "missing-server.pub",
                        "role": "client",
                        "ephemeral_handshake": True,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "cannot access X25519 private key"):
                validate_profile_keys(load_config(profile))


class MainWindowTest(unittest.TestCase):
    def test_profile_populates_connection_details(self) -> None:
        with TemporaryDirectory() as directory:
            profile = Path(directory) / "client.json"
            profile.write_text(
                json.dumps(
                    {
                        "tun_address": "10.0.0.2/30",
                        "bind": "0.0.0.0:51820",
                        "peer": "192.0.2.2:51820",
                    }
                ),
                encoding="utf-8",
            )
            window = MainWindow(EndpointProcess())

            window.set_profile(profile)

            self.assertEqual(window.tunnel_value.text(), "10.0.0.2/30")
            self.assertEqual(window.peer_value.text(), "192.0.2.2:51820")
            self.assertEqual(window.security_value.text(), "Unencrypted baseline")
            self.assertTrue(window.connect_button.isEnabled())
            window.close()

    def test_encrypted_profile_shows_security_details(self) -> None:
        with TemporaryDirectory() as directory:
            profile = Path(directory) / "client.json"
            profile.write_text(
                json.dumps(
                    {
                        "tun_address": "10.8.0.2/24",
                        "bind": "0.0.0.0:51820",
                        "peer": "192.0.2.2:51820",
                        "private_key_file": "client.key",
                        "peer_public_key_file": "server.pub",
                        "role": "client",
                        "ephemeral_handshake": True,
                        "packets_per_key": 100000,
                    }
                ),
                encoding="utf-8",
            )
            window = MainWindow(EndpointProcess())

            window.set_profile(profile)

            self.assertIn("ephemeral X25519", window.security_value.text())
            self.assertIn("100,000", window.security_value.text())
            self.assertFalse(window.connect_button.isEnabled())
            self.assertIn("Profile preview only", window.log_view.toPlainText())
            window.close()


if __name__ == "__main__":
    unittest.main()