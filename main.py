from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Pattern

import pyperclip
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QColor, QIcon, QPalette
from PyQt5.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "SMITE IP Grabber"
ICON_PATH = Path(__file__).with_suffix("").parent / "assets" / "nmap_icon_132152.png"
LOG_NAME_PREFIX = "MCTS-"
EXCLUDED_PORTS: set[str] = {"9000", "443"}

TIMESTAMP_RE: Pattern[str] = re.compile(r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}")
CONNECTION_RE: Pattern[str] = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"
)


@dataclass(frozen=True, slots=True)
class ConnectionData:
    """Parsed connection information found in a log line."""

    timestamp: datetime
    ip: str
    port: str


class Launcher(Enum):
    """Supported SMITE launchers."""

    STEAM = auto()
    EPIC = auto()

    @property
    def log_dir(self) -> Path:
        base = {
            Launcher.STEAM: Path(
                "C:/Program Files (x86)/Steam/steamapps/common/SMITE/Binaries/Logs"
            ),
            Launcher.EPIC: Path(
                "C:/Program Files/Epic Games/SMITE/Binaries/Logs"
            ),
        }[self]
        return base.resolve()


class LogParser:
    """Locate the most‑recent log file and extract connection data."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir

    def latest_log(self) -> Optional[Path]:
        """Return the most recently modified log file or *None*."""
        try:
            return max(
                self.log_dir.glob(f"{LOG_NAME_PREFIX}*"),
                key=lambda p: p.stat().st_mtime,
                default=None,
            )
        except OSError:
            return None

    def extract_connection(self, log_path: Path) -> Optional[ConnectionData]:
        """Scan the log (bottom-up) and return the newest valid connection."""
        try:
            lines = log_path.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, UnicodeDecodeError):
            return None

        for line in reversed(lines):
            if "Connection" not in line and "Connected" not in line:
                continue

            ts_match = TIMESTAMP_RE.search(line)
            conn_match = CONNECTION_RE.search(line)

            if not (ts_match and conn_match):
                continue

            ip, port = conn_match.groups()
            if port in EXCLUDED_PORTS:
                continue

            timestamp = datetime.strptime(ts_match.group(), "%d-%m-%Y %H:%M:%S")
            return ConnectionData(timestamp, ip, port)

        return None


class IPGrabberUI(QWidget):
    """Main application window."""

    STYLESHEET = """
        QWidget { background: #2E2E2E; color: #FFF; font-family: 'Segoe UI'; }
        QPushButton { background: #4A4A4A; border: none; padding: 8px 16px; border-radius: 4px; }
        QPushButton:hover { background: #5A5A5A; }
        QLineEdit { background: #3A3A3A; border: 1px solid #4A4A4A; padding: 6px; border-radius: 4px; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.parser: Optional[LogParser] = None
        self.ip_field: QLineEdit
        self.port_field: QLineEdit

        self._build_ui()
        self._select_launcher()

    def _build_ui(self) -> None:
        self.setWindowIcon(QIcon(str(ICON_PATH)))
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(400, 250)
        self.setStyleSheet(self.STYLESHEET)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(15)

        root.addWidget(self._info_label())
        self.ip_field, self.port_field = self._connection_fields(root)
        self._control_buttons(root)

    def _info_label(self) -> QLabel:
        label = QLabel("Refresh while in‑game for accurate results", self)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-weight: bold; color: #88C0D0;")
        return label

    def _connection_fields(self, layout: QVBoxLayout) -> tuple[QLineEdit, QLineEdit]:
        def make_row(placeholder: str, copy_tip: str) -> QLineEdit:
            field = QLineEdit(self, placeholderText=placeholder, readOnly=True)
            copy_btn = QPushButton(copy_tip, self)
            copy_btn.clicked.connect(lambda: self._to_clipboard(field.text()))

            row = QHBoxLayout()
            row.addWidget(field, 4)
            row.addWidget(copy_btn, 1)
            layout.addLayout(row)
            return field

        return make_row("IP Address", "Copy IP"), make_row("Port", "Copy Port")

    def _control_buttons(self, layout: QVBoxLayout) -> None:
        refresh_btn = QPushButton("Refresh", self)
        refresh_btn.clicked.connect(self._update_connection)

        launcher_btn = QPushButton("Change Launcher", self)
        launcher_btn.clicked.connect(self._select_launcher)

        help_btn = QPushButton("Help", self)
        help_btn.clicked.connect(self._show_help)

        for btn in (refresh_btn, launcher_btn, help_btn):
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            layout.addWidget(btn)

    def _select_launcher(self) -> None:
        choice = self._launcher_dialog()
        if not choice:
            return

        path = choice.log_dir
        if not path.exists():
            QMessageBox.critical(self, "Error", f"Launcher directory not found:\n{path}")
            return

        self.parser = LogParser(path)
        self._update_connection()

    @staticmethod
    def _launcher_dialog() -> Optional[Launcher]:
        dialog = QMessageBox()
        dialog.setWindowIcon(QIcon(str(ICON_PATH)))
        dialog.setWindowTitle("Select Launcher")
        dialog.setText("Choose your SMITE launcher:")

        steam_btn = dialog.addButton("Steam", QMessageBox.YesRole)
        epic_btn = dialog.addButton("Epic Games", QMessageBox.NoRole)
        dialog.exec_()

        if dialog.clickedButton() == steam_btn:
            return Launcher.STEAM
        if dialog.clickedButton() == epic_btn:
            return Launcher.EPIC
        return None

    @pyqtSlot()
    def _update_connection(self) -> None:
        if not self.parser:
            return

        log_file = self.parser.latest_log()
        data = log_file and self.parser.extract_connection(log_file)

        if data:
            self.ip_field.setText(data.ip)
            self.port_field.setText(data.port)
        else:
            self.ip_field.setText("No connection data found")
            self.port_field.clear()

    @staticmethod
    def _to_clipboard(text: str) -> None:  # pragma: no cover
        if text:
            pyperclip.copy(text)

    @staticmethod
    def _show_help() -> None:  # pragma: no cover
        QMessageBox.information(
            None,
            "Help",
            "Created by 54b3r\nFor support contact me on Discord.",
        )

def main() -> None:  # pragma: no cover
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#2E2E2E"))
    palette.setColor(QPalette.WindowText, Qt.white)
    app.setPalette(palette)

    window = IPGrabberUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
