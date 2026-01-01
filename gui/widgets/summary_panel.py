"""Summary panel showing check statistics."""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QProgressBar, QFrame
)
from PyQt6.QtCore import Qt

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import CheckStatus


class SummaryPanel(QWidget):
    """Panel displaying pass/fail/warning counts and overall status."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)

        # Status counts
        self.passed_label = QLabel("Passed: 0")
        self.passed_label.setStyleSheet("color: #00cc00; font-weight: bold; font-size: 14px;")

        self.failed_label = QLabel("Failed: 0")
        self.failed_label.setStyleSheet("color: #cc0000; font-weight: bold; font-size: 14px;")

        self.warning_label = QLabel("Warnings: 0")
        self.warning_label.setStyleSheet("color: #ccaa00; font-weight: bold; font-size: 14px;")

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)

        # Overall status
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-size: 14px;")

        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)

        # Progress text
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)

        layout.addWidget(self.passed_label)
        layout.addWidget(self.failed_label)
        layout.addWidget(self.warning_label)
        layout.addWidget(separator)
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_bar)

    def update_summary(self, checks: list):
        """Update summary with check results."""
        passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
        failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        warnings = sum(1 for c in checks if c.status == CheckStatus.WARNING)
        skipped = sum(1 for c in checks if c.status == CheckStatus.SKIPPED)

        self.passed_label.setText(f"Passed: {passed}")
        self.failed_label.setText(f"Failed: {failed}")
        self.warning_label.setText(f"Warnings: {warnings}")

        # Update overall status
        if failed == 0 and warnings == 0:
            self.status_label.setText("System Ready for Gaming!")
            self.status_label.setStyleSheet("color: #00cc00; font-size: 14px; font-weight: bold;")
        elif failed == 0:
            self.status_label.setText("Review Warnings")
            self.status_label.setStyleSheet("color: #ccaa00; font-size: 14px; font-weight: bold;")
        else:
            self.status_label.setText("Fixes Required")
            self.status_label.setStyleSheet("color: #cc0000; font-size: 14px; font-weight: bold;")

    def show_progress(self, message: str, percent: int):
        """Show progress during check operation."""
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.progress_bar.setValue(percent)
        self.progress_label.setText(message)

    def hide_progress(self):
        """Hide progress indicators."""
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)

    def reset(self):
        """Reset to initial state."""
        self.passed_label.setText("Passed: 0")
        self.failed_label.setText("Failed: 0")
        self.warning_label.setText("Warnings: 0")
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("font-size: 14px;")
        self.hide_progress()
