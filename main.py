from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Pattern

# Attempt to import pyperclip and handle its absence
try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False
    pyperclip = None  # Define it as None to avoid NameErrors later

# Third-party imports (PyQt5)
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
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
ICON_PATH = ASSETS_DIR / "nmap_icon_132152.png"
LOG_NAME_PREFIX = "MCTS-"
EXCLUDED_PORTS: set[str] = {"9000", "443"}

TIMESTAMP_RE: Pattern[str] = re.compile(r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}")
CONNECTION_RE: Pattern[str] = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"  # IP:Port
)


@dataclass(frozen=True, slots=True)
class ConnectionData:
    """Parsed connection information found in a log line."""
    timestamp: datetime
    ip: str
    port: str


class Launcher(Enum):
    """
    Supported SMITE launchers.

    Note: Log directory paths are hardcoded for default Windows installations.
          This may not work on other OS or with custom install locations.
    """
    STEAM = auto()
    EPIC = auto()

    @property
    def log_dir(self) -> Path:
        """Return the resolved log directory path for the launcher."""
        # Using a mapping for cleaner association
        path_map = {
            Launcher.STEAM: Path(
                "C:/Program Files (x86)/Steam/steamapps/common/SMITE/Binaries/Logs"
            ),
            Launcher.EPIC: Path(
                "C:/Program Files/Epic Games/SMITE/Binaries/Logs"
            ),
        }
        # Use resolve() to get the absolute path and handle potential symlinks etc.
        # The [self] lookup gets the path corresponding to the enum member
        return path_map[self].resolve()


class LogParser:
    """Locate the most-recent log file and extract connection data."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        if not self.log_dir.is_dir():
            # Raise an error early if the directory isn't valid
            raise FileNotFoundError(f"Log directory does not exist: {log_dir}")

    def find_latest_log(self) -> Optional[Path]:
        """
        Return the most recently modified log file matching the prefix.
        Returns None if no matching files are found or an OS error occurs.
        """
        try:
            log_files = list(self.log_dir.glob(f"{LOG_NAME_PREFIX}*"))
            if not log_files:
                return None
            # Find the file with the maximum modification time
            return max(log_files, key=lambda p: p.stat().st_mtime)
        except OSError as e:
            # Log or handle specific OS errors if needed
            print(f"Error accessing log directory {self.log_dir}: {e}", file=sys.stderr)
            return None

    def extract_connection(self, log_path: Path) -> Optional[ConnectionData]:
        """
        Scan the log file (from bottom to top) for the newest valid connection.

        Reads the entire file into memory. For extremely large log files,
        a memory-optimized approach (reading chunks from the end) might be
        considered, but adds complexity.

        Returns:
            ConnectionData if a valid, non-excluded connection is found,
            otherwise None.
        """
        try:
            # Read all lines at once. Handle potential encoding issues.
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except FileNotFoundError:
            print(f"Error: Log file not found: {log_path}", file=sys.stderr)
            return None
        except UnicodeDecodeError as e:
            print(f"Error decoding log file {log_path}: {e}", file=sys.stderr)
            return None
        except OSError as e: # Catch other potential IO errors
             print(f"Error reading log file {log_path}: {e}", file=sys.stderr)
             return None

        # Iterate backwards through the lines to find the most recent entry first
        for line in reversed(lines):
            # Quick check for relevant keywords
            if "Connection" not in line and "Connected" not in line:
                continue

            # Search for timestamp and connection info using pre-compiled regex
            ts_match = TIMESTAMP_RE.search(line)
            conn_match = CONNECTION_RE.search(line)

            # Both parts must be found to proceed
            if not (ts_match and conn_match):
                continue

            ip, port = conn_match.groups()

            # Skip if the port is in the exclusion list
            if port in EXCLUDED_PORTS:
                continue

            # Try to parse the timestamp
            try:
                timestamp = datetime.strptime(ts_match.group(), "%d-%m-%Y %H:%M:%S")
                # Found a valid entry, return it
                return ConnectionData(timestamp=timestamp, ip=ip, port=port)
            except ValueError:
                # Log timestamp parsing error if needed
                print(f"Warning: Could not parse timestamp in line: {line}", file=sys.stderr)
                continue # Continue searching if timestamp format is wrong

        # No suitable connection found in the entire file
        return None


class IPGrabberUI(QWidget):
    """Main application window."""

    STYLESHEET = """
        QWidget { background-color: #2E2E2E; color: #FFFFFF; font-family: 'Segoe UI', Arial, sans-serif; }
        QPushButton { background-color: #4A4A4A; border: none; padding: 8px 16px; border-radius: 4px; }
        QPushButton:hover { background-color: #5A5A5A; }
        QPushButton:pressed { background-color: #6A6A6A; }
        QPushButton:disabled { background-color: #3A3A3A; color: #777777; }
        QLineEdit { background-color: #3A3A3A; border: 1px solid #4A4A4A; padding: 6px; border-radius: 4px; color: #FFFFFF; }
        QLineEdit:read-only { background-color: #333333; }
        QLabel#infoLabel { color: #88C0D0; font-weight: bold; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.parser: Optional[LogParser] = None
        # Explicitly define fields for clarity
        self.ip_field: QLineEdit | None = None
        self.port_field: QLineEdit | None = None
        self.copy_ip_button: QPushButton | None = None
        self.copy_port_button: QPushButton | None = None
        self.refresh_button: QPushButton | None = None

        self._setup_window()
        self._build_ui()
        self._select_launcher() # Initial prompt for launcher

    def _setup_window(self) -> None:
        """Sets basic window properties like title, icon, size, style."""
        self.setWindowTitle(APP_NAME)
        try:
            if ICON_PATH.is_file():
                 self.setWindowIcon(QIcon(str(ICON_PATH)))
            else:
                 print(f"Warning: Icon file not found at {ICON_PATH}", file=sys.stderr)
        except OSError as e:
            print(f"Error loading icon: {e}", file=sys.stderr)

        self.setMinimumSize(400, 220) # Adjusted slightly
        self.setStyleSheet(self.STYLESHEET)

    def _build_ui(self) -> None:
        """Creates and arranges the widgets in the main window."""
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(20, 20, 20, 20)
        root_layout.setSpacing(15)

        # Informational Label
        info_label = QLabel("Refresh while in-game for accurate results", self)
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setObjectName("infoLabel") # For specific styling
        root_layout.addWidget(info_label)

        # IP and Port display rows
        self.ip_field, self.copy_ip_button = self._create_display_row(
            "IP Address", "Copy IP"
        )
        self.port_field, self.copy_port_button = self._create_display_row(
            "Port", "Copy Port"
        )

        # Add rows to the main layout
        for field, button in [(self.ip_field, self.copy_ip_button), (self.port_field, self.copy_port_button)]:
             if field and button:
                row_layout = QHBoxLayout()
                row_layout.addWidget(field, stretch=4) # Field takes more space
                row_layout.addWidget(button, stretch=1)
                root_layout.addLayout(row_layout)

        # Control Buttons
        self._create_control_buttons(root_layout)

        # Initial state: Disable copy/refresh until parser is ready
        self._set_controls_enabled(False)

    def _create_display_row(self, placeholder: str, button_text: str) -> tuple[QLineEdit, QPushButton]:
        """Helper to create a QLineEdit (read-only) and a copy QPushButton row."""
        field = QLineEdit(self, placeholderText=placeholder, readOnly=True)
        copy_button = QPushButton(button_text, self)

        # Connect button click to copy action, handle missing pyperclip
        copy_button.clicked.connect(lambda: self._copy_field_to_clipboard(field))
        if not PYPERCLIP_AVAILABLE:
            copy_button.setToolTip("Install 'pyperclip' library to enable copying.")
            copy_button.setEnabled(False) # Disable if pyperclip not installed

        return field, copy_button

    def _create_control_buttons(self, layout: QVBoxLayout) -> None:
        """Creates and adds Refresh, Change Launcher, and Help buttons."""
        self.refresh_button = QPushButton("Refresh", self)
        self.refresh_button.clicked.connect(self._update_connection)

        launcher_button = QPushButton("Change Launcher", self)
        launcher_button.clicked.connect(self._select_launcher)

        help_button = QPushButton("Help", self)
        help_button.clicked.connect(self._show_help_dialog)

        # Add buttons to layout, making them expand horizontally
        for btn in (self.refresh_button, launcher_button, help_button):
             if btn:
                btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                layout.addWidget(btn)

    def _set_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable controls that depend on a valid parser/data."""
        if self.refresh_button:
            self.refresh_button.setEnabled(enabled)
        if self.copy_ip_button and PYPERCLIP_AVAILABLE:
            self.copy_ip_button.setEnabled(enabled)
        if self.copy_port_button and PYPERCLIP_AVAILABLE:
            self.copy_port_button.setEnabled(enabled)
        # Text fields are always visible, just potentially empty

    @pyqtSlot()
    def _select_launcher(self) -> None:
        """Prompts the user to select a launcher and initializes LogParser."""
        chosen_launcher = self._show_launcher_selection_dialog()
        if not chosen_launcher:
             # User cancelled or closed dialog; if no parser exists yet, maybe close app or disable?
             if not self.parser:
                 QMessageBox.warning(self, "Launcher Required", "Please select a launcher to proceed.")
                 # Optionally: sys.exit() or self.close() if launcher is mandatory at start
             return # Keep existing parser if one was already set

        try:
            log_directory = chosen_launcher.log_dir
            # Initialize or update the parser
            self.parser = LogParser(log_directory)
            self.setWindowTitle(f"{APP_NAME} - {chosen_launcher.name.capitalize()}")
            self._set_controls_enabled(True) # Enable controls now
            self._update_connection() # Perform initial fetch
        except FileNotFoundError as e:
            QMessageBox.critical(
                self, "Directory Error", f"Log directory not found:\n{e}"
            )
            self.parser = None # Reset parser on error
            self._set_controls_enabled(False) # Disable controls
            self._clear_fields()
        except Exception as e: # Catch other potential init errors
             QMessageBox.critical(
                self, "Initialization Error", f"Failed to initialize parser:\n{e}"
            )
             self.parser = None
             self._set_controls_enabled(False)
             self._clear_fields()


    def _show_launcher_selection_dialog(self) -> Optional[Launcher]:
        """Shows a dialog to choose between Steam and Epic launchers."""
        dialog = QMessageBox(self) # Parent to self
        try: # Set icon for dialog too
             if ICON_PATH.is_file():
                dialog.setWindowIcon(QIcon(str(ICON_PATH)))
        except OSError:
             pass # Ignore icon error for dialog
        dialog.setWindowTitle("Select Launcher")
        dialog.setText("Choose your SMITE launcher installation:")
        dialog.setIcon(QMessageBox.Question)

        # Add buttons with specific roles for clarity
        steam_button = dialog.addButton("Steam", QMessageBox.YesRole)
        epic_button = dialog.addButton("Epic Games", QMessageBox.NoRole)
        dialog.addButton(QMessageBox.Cancel)

        dialog.exec_() # Show the dialog modally

        clicked_btn = dialog.clickedButton()
        if clicked_btn == steam_button:
            return Launcher.STEAM
        elif clicked_btn == epic_button:
            return Launcher.EPIC
        else: # Cancelled or closed
            return None

    @pyqtSlot()
    def _update_connection(self) -> None:
        """Fetches the latest log and updates the IP/Port fields."""
        if not self.parser:
            QMessageBox.warning(self, "Setup Required", "Please select a launcher first.")
            return

        latest_log_path = self.parser.find_latest_log()
        connection_info: Optional[ConnectionData] = None

        if latest_log_path:
            # Only try to extract if a log file was found
            connection_info = self.parser.extract_connection(latest_log_path)
            if not connection_info:
                 print(f"Info: No valid connection data found in {latest_log_path.name}", file=sys.stderr)

        elif not latest_log_path:
             print(f"Info: No log files found in {self.parser.log_dir}", file=sys.stderr)

        # Update UI based on whether data was found
        if connection_info and self.ip_field and self.port_field:
            self.ip_field.setText(connection_info.ip)
            self.port_field.setText(connection_info.port)
            self.ip_field.setToolTip(f"Last updated: {connection_info.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            self.port_field.setToolTip(f"Last updated: {connection_info.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
             self._clear_fields("No connection data found")


    def _clear_fields(self, ip_message: str = "") -> None:
         """Clears the IP and Port fields."""
         if self.ip_field:
              self.ip_field.setText(ip_message)
              self.ip_field.setToolTip("")
         if self.port_field:
              self.port_field.clear()
              self.port_field.setToolTip("")


    @pyqtSlot()
    def _copy_field_to_clipboard(self, field: QLineEdit) -> None: # pragma: no cover
        """Copies the text from the given QLineEdit to the clipboard."""
        text_to_copy = field.text()
        if text_to_copy and PYPERCLIP_AVAILABLE and pyperclip:
            try:
                pyperclip.copy(text_to_copy)
                # Optional: Provide user feedback (e.g., status bar message)
                print(f"Copied to clipboard: {text_to_copy}")
            except Exception as e: # Catch potential pyperclip errors
                print(f"Error copying to clipboard: {e}", file=sys.stderr)
                QMessageBox.warning(self, "Clipboard Error", f"Could not copy to clipboard:\n{e}")
        elif not PYPERCLIP_AVAILABLE:
             QMessageBox.warning(self, "Missing Library", "Copying requires the 'pyperclip' library.\nPlease install it (`pip install pyperclip`).")


    @staticmethod
    def _show_help_dialog() -> None: # pragma: no cover
        """Displays a simple help/about message box."""
        # Parent set to None to make it an independent dialog
        QMessageBox.information(
            None, # Parent
            "Help / About", # Window Title
            f"{APP_NAME}\n\n"
            "This tool finds the latest SMITE match server IP address by reading game logs.\n\n"
            "1. Select your launcher (Steam or Epic).\n"
            "2. Click 'Refresh' while in a SMITE match.\n"
            "3. Use the 'Copy' buttons to copy the IP or Port.\n\n"
            "Created by 54b3r - For support, contact on Discord.",
        )


def main() -> None: # pragma: no cover
    """Initializes and runs the PyQt5 application."""
    app = QApplication(sys.argv)

    if "Fusion" in QApplication.style().objectName():
         app.setStyle("Fusion")
    else:
        print("Fusion style not available, using default.", file=sys.stderr)

    window = IPGrabberUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
