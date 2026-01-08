#!/usr/bin/env python3
"""Steam Proton Helper GUI - Entry Point."""

import atexit
import fcntl
import os
import sys
from pathlib import Path

# Single-instance lock
LOCK_FILE = Path.home() / ".cache" / "steam-proton-helper-gui.lock"
_lock_file_handle = None


def acquire_instance_lock() -> bool:
    """Try to acquire single-instance lock. Returns True if acquired."""
    global _lock_file_handle
    try:
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        _lock_file_handle = open(LOCK_FILE, "w")
        fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_file_handle.write(str(os.getpid()))
        _lock_file_handle.flush()
        return True
    except (IOError, OSError):
        if _lock_file_handle:
            _lock_file_handle.close()
            _lock_file_handle = None
        return False


def release_instance_lock():
    """Release the single-instance lock."""
    global _lock_file_handle
    if _lock_file_handle:
        try:
            fcntl.flock(_lock_file_handle.fileno(), fcntl.LOCK_UN)
            _lock_file_handle.close()
        except (IOError, OSError):
            pass
        _lock_file_handle = None


def main():
    """Launch the Steam Proton Helper GUI."""
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtCore import Qt
    except ImportError:
        print("Error: PyQt6 is required for the GUI.")
        print("Install with: pip install PyQt6")
        sys.exit(1)

    # Single-instance check
    if not acquire_instance_lock():
        app = QApplication(sys.argv)
        QMessageBox.warning(
            None,
            "Already Running",
            "Steam Proton Helper GUI is already running.",
        )
        sys.exit(1)

    atexit.register(release_instance_lock)

    from gui import MainWindow

    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Steam Proton Helper")
    app.setApplicationVersion("2.3.3")
    app.setOrganizationName("AreteDriver")

    # Set application style
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
