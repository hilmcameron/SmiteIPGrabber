import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, NamedTuple

from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QMessageBox,
    QLineEdit,
    QSizePolicy,
)
from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5.QtGui import QIcon, QPalette, QColor

import pyperclip

class ConnectionData(NamedTuple):
    """Container for parsed connection information."""
    timestamp: datetime
    ip: str
    port: str

class LauncherManager:
    """Handles detection and validation of game launcher paths."""
    STEAM_DIR = Path("C:/Program Files (x86)/Steam/steamapps/common/SMITE/Binaries/Logs")
    EPIC_DIR = Path("C:/Program Files/Epic Games/SMITE/Binaries/Logs")
    ICON_PATH = Path(__file__).parent / "assets" / "nmap_icon_132152.png"

    @classmethod
    def get_launcher_path(cls) -> Path:
        """Displays dialog to select game launcher."""
        dialog = QMessageBox()
        dialog.setWindowIcon(QIcon(str(cls.ICON_PATH)))
        dialog.setWindowTitle("Select Launcher")
        dialog.setText("Choose your SMITE launcher:")

        steam_btn = dialog.addButton("Steam", QMessageBox.YesRole)
        epic_btn = dialog.addButton("Epic Games", QMessageBox.NoRole)

        dialog.exec_()

        selected_path = cls.STEAM_DIR if dialog.clickedButton() == steam_btn else cls.EPIC_DIR
        if not selected_path.exists():
            raise FileNotFoundError(f"Launcher directory not found: {selected_path}")
        return selected_path

class LogParser:
    """Handles log file parsing and data extraction."""
    LOG_PREFIX = "MCTS-"
    TIMESTAMP_REGEX = re.compile(r"(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})")
    CONNECTION_REGEX = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)")
    EXCLUDED_PORTS = {"9000", "443"}

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir

    def find_latest_log(self) -> Optional[Path]:
        """Find the latest log file in the directory."""
        try:
            return max(
                self.log_dir.glob(f"{self.LOG_PREFIX}*"),
                key=lambda p: p.stat().st_mtime,
                default=None
            )
        except (OSError, ValueError):
            return None

    def extract_connection_data(self, log_path: Path) -> Optional[ConnectionData]:
        """Extract connection data from the log file."""
        try:
            with log_path.open("r", encoding="utf-8") as file:
                for line in reversed(file.readlines()):
                    if self._is_valid_line(line):
                        return self._parse_line(line)
        except (IOError, UnicodeDecodeError):
            pass
        return None

    def _is_valid_line(self, line: str) -> bool:
        """Check if the line contains valid connection data."""
        return "Connection" in line or "Connected" in line

    def _parse_line(self, line: str) -> Optional[ConnectionData]:
        """Parse the line to extract connection data."""
        ts_match = self.TIMESTAMP_REGEX.search(line)
        conn_match = self.CONNECTION_REGEX.search(line)

        if ts_match and conn_match:
            ip, port = conn_match.groups()
            if port not in self.EXCLUDED_PORTS:
                timestamp = datetime.strptime(ts_match.group(), "%d-%m-%Y %H:%M:%S")
                return ConnectionData(timestamp, ip, port)
        return None

class IPGrabberUI(QWidget):
    """Main application GUI."""
    STYLESHEET = """
        QWidget {
            background-color: #2E2E2E;
            color: #FFFFFF;
            font-family: 'Segoe UI';
        }
        QPushButton {
            background-color: #4A4A4A;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #5A5A5A;
        }
        QLineEdit {
            background-color: #3A3A3A;
            border: 1px solid #4A4A4A;
            padding: 6px;
            color: #FFFFFF;
            border-radius: 4px;
        }
    """

    def __init__(self):
        super().__init__()
        self.log_parser: Optional[LogParser] = None
        self._configure_ui()
        self._select_launcher()

    def _configure_ui(self) -> None:
        """Configure the UI components."""
        self.setWindowIcon(QIcon(str(LauncherManager.ICON_PATH)))
        self.setWindowTitle("SMITE IP Grabber")
        self.setMinimumSize(400, 250)
        self.setStyleSheet(self.STYLESHEET)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        self._create_info_label(layout)
        self.ip_field, self.port_field = self._create_input_fields(layout)
        self._create_control_buttons(layout)

        self.setLayout(layout)

    def _create_info_label(self, layout: QVBoxLayout) -> None:
        """Create the info label."""
        info_label = QLabel("Refresh while in-game for accurate results")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("font-weight: bold; color: #88C0D0;")
        layout.addWidget(info_label)

    def _create_input_fields(self, layout: QVBoxLayout) -> Tuple[QLineEdit, QLineEdit]:
        """Create the input fields."""
        ip_field = self._create_field("IP Address", "Copy IP", layout)
        port_field = self._create_field("Port", "Copy Port", layout)
        return ip_field, port_field

    def _create_field(self, placeholder: str, btn_text: str, layout: QVBoxLayout) -> QLineEdit:
        """Create a field with a copy button."""
        field = QLineEdit(self)
        field.setPlaceholderText(placeholder)
        field.setReadOnly(True)

        copy_btn = QPushButton(btn_text, self)
        copy_btn.clicked.connect(lambda: self._copy_to_clipboard(field.text()))

        field_layout = QHBoxLayout()
        field_layout.addWidget(field, 4)
        field_layout.addWidget(copy_btn, 1)
        layout.addLayout(field_layout)

        return field

    def _create_control_buttons(self, layout: QVBoxLayout) -> None:
        """Create the control buttons."""
        self.refresh_btn = QPushButton("Refresh", self)
        self.refresh_btn.clicked.connect(self._update_connection_info)

        self.launcher_btn = QPushButton("Change Launcher", self)
        self.launcher_btn.clicked.connect(self._select_launcher)

        help_btn = QPushButton("Help", self)
        help_btn.clicked.connect(self._show_help)

        for btn in [self.refresh_btn, self.launcher_btn, help_btn]:
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            layout.addWidget(btn)

    def _select_launcher(self) -> None:
        """Select the game launcher."""
        try:
            if path := LauncherManager.get_launcher_path():
                self.log_parser = LogParser(path)
                self._update_connection_info()
        except FileNotFoundError as e:
            QMessageBox.critical(self, "Error", str(e))

    @pyqtSlot()
    def _update_connection_info(self) -> None:
        """Update the connection info."""
        if not self.log_parser:
            return

        if log_path := self.log_parser.find_latest_log():
            if data := self.log_parser.extract_connection_data(log_path):
                self.ip_field.setText(data.ip)
                self.port_field.setText(data.port)
                return

        self.ip_field.setText("No connection data found")
        self.port_field.clear()

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        """Copy text to clipboard."""
        if text:
            pyperclip.copy(text)

    @staticmethod
    def _show_help() -> None:
        """Show help message."""
        QMessageBox.information(
            None,
            "Help",
            "Created by 54b3r\nFor support contact me on discord",
            QMessageBox.Ok
        )

def main() -> None:
    """Main entry point."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(46, 46, 46))
    palette.setColor(QPalette.WindowText, Qt.white)
    app.setPalette(palette)

    window = IPGrabberUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    print(r"""
     ____            _ _         ___ ____     ____           _     _               
    / ___| _ __ ___ (_) |_ ___  |_ _|  _ \   / ___|_ __ __ _| |__ | |__   ___ _ __
    \___ \| '_ ` _ \| | __/ _ \  | || |_) | | |  _| '__/ _` | '_ \| '_ \/ _ \ '__|
     ___) | | | | | | | ||  __/  | ||  __/  | |_| | | | (_| | |_) | |_) |  __/ |
    |____/|_| |_| |_|_|\__\___| |___|_|      \____|_|  \__,_|_.__/|_.__/ \___|_|

            Made by 54b3r -> For help add me on discord.
    """)
    main()
