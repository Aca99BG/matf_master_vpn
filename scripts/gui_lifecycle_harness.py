"""Drive the real PyQt client through connect and disconnect for smoke tests."""

import argparse
from pathlib import Path
import sys

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QApplication

from matf_vpn.gui import MainWindow


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--disconnect-file", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    options = parser.parse_args()

    application = QApplication([])
    window = MainWindow()
    window.set_profile(options.profile)
    deadline_ms = int(options.timeout * 1000)
    elapsed_ms = 0

    def record_state(state: str) -> None:
        with options.state_file.open("a", encoding="utf-8") as state_file:
            state_file.write(state + "\n")
        if state == "error":
            application.exit(1)

    def monitor() -> None:
        nonlocal elapsed_ms
        elapsed_ms += 50
        if options.disconnect_file.exists() and window.controller.state == "connected":
            window.disconnect_button.click()
            options.disconnect_file.unlink()
        if window.controller.state == "disconnected" and "connected" in _states(options.state_file):
            window.close()
            application.exit(0)
            return
        if elapsed_ms >= deadline_ms:
            application.exit(2)

    window.controller.state_changed.connect(record_state)
    window.show()
    QTimer.singleShot(0, window.connect_button.click)
    timer = QTimer()
    timer.timeout.connect(monitor)
    timer.start(50)
    return application.exec_()


def _states(path: Path):
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


if __name__ == "__main__":
    raise SystemExit(main())