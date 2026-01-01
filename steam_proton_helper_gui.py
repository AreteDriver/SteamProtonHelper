#!/usr/bin/env python3
"""Steam Proton Helper GUI - Entry Point."""

import sys


def main():
    """Launch the Steam Proton Helper GUI."""
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
    except ImportError:
        print("Error: PyQt6 is required for the GUI.")
        print("Install with: pip install PyQt6")
        sys.exit(1)

    from gui import MainWindow

    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Steam Proton Helper")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("AreteDriver")

    # Set application style
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
