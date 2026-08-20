"""PyQt graphical client for managing a VPN endpoint."""

import argparse
import json
from pathlib import Path
import sys
from typing import Dict, Optional

from PyQt5.QtCore import QObject, QProcess, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QCloseEvent, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from matf_vpn.cli import load_preshared_key, load_x25519_key
from matf_vpn.config import EndpointConfig, load_config


class EndpointProcess(QObject):
    state_changed = pyqtSignal(str)
    event_received = pyqtSignal(dict)
    error_received = pyqtSignal(str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.SeparateChannels)
        self.process.readyReadStandardError.connect(self._read_standard_error)
        self.process.readyReadStandardOutput.connect(self._read_standard_output)
        self.process.errorOccurred.connect(self._on_process_error)
        self.process.finished.connect(self._on_finished)
        self._stderr_buffer = ""
        self._stdout_buffer = ""
        self._state = "disconnected"
        self._stopping = False

    @property
    def state(self) -> str:
        return self._state

    def start(self, profile: Path) -> EndpointConfig:
        if self.process.state() != QProcess.NotRunning:
            raise RuntimeError("VPN endpoint is already running")
        config = load_config(profile)
        validate_profile_keys(config)
        source_root = Path(__file__).resolve().parents[1]
        arguments = [
            "/usr/bin/env",
            f"PYTHONPATH={source_root}",
            sys.executable,
            "-m",
            "matf_vpn",
            "--config",
            str(profile.resolve()),
        ]
        self._stopping = False
        self._set_state("connecting")
        self.process.start("pkexec", arguments)
        return config

    def stop(self) -> None:
        if self.process.state() == QProcess.NotRunning:
            return
        self._stopping = True
        self._set_state("stopping")
        self.process.terminate()
        QTimer.singleShot(3000, self._kill_if_running)

    def consume_log_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self.error_received.emit(line)
            return
        if not isinstance(event, dict):
            self.error_received.emit(line)
            return

        event_name = event.get("event")
        if event_name == "session_established":
            self._set_state("connected")
        elif event_name == "reconnect_scheduled":
            self._set_state("reconnecting")
        elif event_name == "endpoint_stopped":
            self._set_state("disconnected")
        self.event_received.emit(event)

    def _read_standard_error(self) -> None:
        self._stderr_buffer += bytes(self.process.readAllStandardError()).decode(
            "utf-8",
            errors="replace",
        )
        self._stderr_buffer = self._consume_buffer(self._stderr_buffer)

    def _read_standard_output(self) -> None:
        self._stdout_buffer += bytes(self.process.readAllStandardOutput()).decode(
            "utf-8",
            errors="replace",
        )
        self._stdout_buffer = self._consume_buffer(self._stdout_buffer)

    def _consume_buffer(self, buffer: str) -> str:
        lines = buffer.split("\n")
        for line in lines[:-1]:
            self.consume_log_line(line)
        return lines[-1]

    def _on_process_error(self, error: QProcess.ProcessError) -> None:
        self.error_received.emit(self.process.errorString())
        if error == QProcess.FailedToStart:
            self._set_state("error")

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        if self._stderr_buffer:
            self.consume_log_line(self._stderr_buffer)
            self._stderr_buffer = ""
        if self._stdout_buffer:
            self.consume_log_line(self._stdout_buffer)
            self._stdout_buffer = ""
        if self._stopping or exit_code == 0:
            self._set_state("disconnected")
        else:
            self._set_state("error")
            self.error_received.emit(f"Endpoint exited with code {exit_code}")

    def _kill_if_running(self) -> None:
        if self.process.state() != QProcess.NotRunning:
            self.process.kill()

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)


class MainWindow(QMainWindow):
    STATE_LABELS = {
        "disconnected": "Disconnected",
        "connecting": "Connecting",
        "connected": "Connected",
        "reconnecting": "Reconnecting",
        "stopping": "Stopping",
        "error": "Connection error",
    }

    def __init__(self, controller: Optional[EndpointProcess] = None) -> None:
        super().__init__()
        self.controller = controller or EndpointProcess(self)
        self.profile_path: Optional[Path] = None
        self._profile_ready = False
        self.setWindowTitle("MATF VPN")
        self.setMinimumSize(760, 560)
        self.resize(860, 620)
        self._build_ui()
        self._connect_signals()
        self._apply_style()
        self._set_state("disconnected")

    def set_profile(self, path: Path) -> None:
        config = load_config(path)
        self.profile_path = path
        self.profile_edit.setText(str(path))
        self.tunnel_value.setText(config.tun_address)
        self.peer_value.setText(f"{config.peer[0]}:{config.peer[1]}")
        self.security_value.setText(self._security_label(config))
        try:
            validate_profile_keys(config)
        except ValueError as error:
            self._profile_ready = False
            self.connect_button.setToolTip(str(error))
            self._append_error(f"Profile preview only: {error}")
        else:
            self._profile_ready = True
            self.connect_button.setToolTip("Connect to the configured VPN peer")
        self._set_state(self.controller.state)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        header = QHBoxLayout()
        title = QLabel("MATF VPN")
        title.setObjectName("title")
        header.addWidget(title)
        header.addStretch()
        self.status_dot = QLabel()
        self.status_dot.setFixedSize(10, 10)
        self.status_label = QLabel()
        self.status_label.setObjectName("statusLabel")
        header.addWidget(self.status_dot)
        header.addWidget(self.status_label)
        layout.addLayout(header)

        profile_layout = QHBoxLayout()
        self.profile_edit = QLineEdit()
        self.profile_edit.setReadOnly(True)
        self.profile_edit.setPlaceholderText("Select a VPN profile")
        self.browse_button = QPushButton()
        self.browse_button.setObjectName("iconButton")
        self.browse_button.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        self.browse_button.setToolTip("Select configuration profile")
        profile_layout.addWidget(self.profile_edit, 1)
        profile_layout.addWidget(self.browse_button)
        layout.addLayout(profile_layout)

        details = QFrame()
        details.setObjectName("details")
        details_layout = QFormLayout(details)
        details_layout.setContentsMargins(20, 18, 20, 18)
        details_layout.setSpacing(12)
        self.tunnel_value = QLabel("Not configured")
        self.peer_value = QLabel("Not configured")
        self.security_value = QLabel("Not configured")
        details_layout.addRow("Tunnel address", self.tunnel_value)
        details_layout.addRow("Remote peer", self.peer_value)
        details_layout.addRow("Security", self.security_value)
        layout.addWidget(details)

        actions = QHBoxLayout()
        self.connect_button = QPushButton("Connect")
        self.connect_button.setObjectName("primaryButton")
        self.connect_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        actions.addWidget(self.connect_button)
        actions.addWidget(self.disconnect_button)
        actions.addStretch()
        layout.addLayout(actions)

        log_label = QLabel("Session log")
        log_label.setObjectName("sectionLabel")
        layout.addWidget(log_label)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(1000)
        layout.addWidget(self.log_view, 1)
        self.setCentralWidget(central)

    def _connect_signals(self) -> None:
        self.browse_button.clicked.connect(self._browse_profile)
        self.connect_button.clicked.connect(self._connect_endpoint)
        self.disconnect_button.clicked.connect(self.controller.stop)
        self.controller.state_changed.connect(self._set_state)
        self.controller.event_received.connect(self._append_event)
        self.controller.error_received.connect(self._append_error)

    def _browse_profile(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select VPN profile",
            "",
            "JSON profiles (*.json)",
        )
        if not filename:
            return
        try:
            self.set_profile(Path(filename))
        except ValueError as error:
            QMessageBox.critical(self, "Invalid VPN profile", str(error))

    def _connect_endpoint(self) -> None:
        if self.profile_path is None:
            return
        try:
            self.controller.start(self.profile_path)
        except (OSError, RuntimeError, ValueError) as error:
            self._append_error(str(error))
            self._set_state("error")

    def _set_state(self, state: str) -> None:
        self.status_label.setText(self.STATE_LABELS.get(state, state.title()))
        self.status_dot.setProperty("connectionState", state)
        self.status_dot.style().unpolish(self.status_dot)
        self.status_dot.style().polish(self.status_dot)
        can_connect = (
            state in ("disconnected", "error")
            and self.profile_path is not None
            and self._profile_ready
        )
        self.connect_button.setEnabled(can_connect)
        self.disconnect_button.setEnabled(state not in ("disconnected", "error"))
        self.browse_button.setEnabled(state in ("disconnected", "error"))

    def _append_event(self, event: Dict[str, object]) -> None:
        timestamp = str(event.get("timestamp", ""))
        message = str(event.get("message", event.get("event", "event")))
        self.log_view.appendPlainText(f"{timestamp}  {message}".strip())

    def _append_error(self, message: str) -> None:
        self.log_view.appendPlainText(f"ERROR  {message}")

    def _security_label(self, config: EndpointConfig) -> str:
        if config.ephemeral_handshake:
            label = "AES-256-GCM · ephemeral X25519"
        elif config.private_key_file is not None:
            label = "AES-256-GCM · static X25519"
        elif config.key_file is not None:
            label = "AES-256-GCM · preshared key"
        else:
            return "Unencrypted baseline"
        if config.packets_per_key:
            label += f" · rotate every {config.packets_per_key:,} packets"
        return label

    def _apply_style(self) -> None:
        self.setFont(QFont("IBM Plex Sans", 10))
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #f4f7f6; color: #17211f; }
            QLabel#title { font-size: 26px; font-weight: 700; color: #123f39; }
            QLabel#statusLabel { font-weight: 600; }
            QLabel#sectionLabel { font-size: 13px; font-weight: 700; color: #31504b; }
            QLabel[connectionState="connected"] { background: #1f9d75; border-radius: 5px; }
            QLabel[connectionState="connecting"], QLabel[connectionState="reconnecting"] { background: #d89418; border-radius: 5px; }
            QLabel[connectionState="stopping"] { background: #71807d; border-radius: 5px; }
            QLabel[connectionState="error"] { background: #c54c43; border-radius: 5px; }
            QLabel[connectionState="disconnected"] { background: #9aa6a3; border-radius: 5px; }
            QFrame#details { background: #ffffff; border: 1px solid #d7e0de; border-radius: 6px; }
            QLineEdit, QPlainTextEdit { background: #ffffff; border: 1px solid #c9d5d2; border-radius: 5px; padding: 9px; selection-background-color: #176d61; }
            QPlainTextEdit { font-family: "JetBrains Mono", "DejaVu Sans Mono"; font-size: 11px; }
            QPushButton { min-height: 34px; padding: 0 15px; border: 1px solid #b9c7c3; border-radius: 5px; background: #ffffff; }
            QPushButton:hover { background: #e9efed; }
            QPushButton:disabled { color: #94a09d; background: #eef2f1; }
            QPushButton#primaryButton { color: #ffffff; background: #176d61; border-color: #176d61; font-weight: 700; }
            QPushButton#primaryButton:hover { background: #12584f; }
            QPushButton#iconButton { min-width: 38px; max-width: 38px; padding: 0; }
            """
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        self.controller.stop()
        event.accept()


def validate_profile_keys(config: EndpointConfig) -> None:
    if config.key_file is not None:
        load_preshared_key(config.key_file)
    if config.private_key_file is not None:
        load_x25519_key(config.private_key_file, private=True)
    if config.peer_public_key_file is not None:
        load_x25519_key(config.peer_public_key_file, private=False)


def main(arguments: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path)
    options = parser.parse_args(arguments)
    application = QApplication(sys.argv)
    application.setApplicationName("MATF VPN")
    window = MainWindow()
    if options.profile is not None:
        try:
            window.set_profile(options.profile)
        except ValueError as error:
            QMessageBox.critical(window, "Invalid VPN profile", str(error))
    window.show()
    return application.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
