"""Checks panel with tree view for dependency checks."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QComboBox, QHBoxLayout, QLabel, QPushButton
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import CheckStatus


class ChecksPanel(QWidget):
    """Panel displaying dependency checks in a tree view."""

    fix_requested = pyqtSignal()  # Emitted when user wants to fix issues

    # Category groupings for checks
    CATEGORIES = {
        "System": ["kernel", "cpu", "memory", "disk"],
        "Steam": ["steam", "steam_runtime", "steam_native"],
        "Proton": ["proton", "ge_proton", "proton_experimental"],
        "Graphics": ["vulkan", "mesa", "nvidia", "amd", "gpu", "driver", "opengl", "glx"],
        "32-bit Support": ["lib32", "multilib", "i386", "wine32"],
        "Gaming Tools": ["gamemode", "mangohud", "gamescope", "corectrl"],
        "Wine": ["wine", "winetricks"],
        "DXVK/VKD3D": ["dxvk", "vkd3d"],
        "Other": [],  # Catch-all
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checks = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Categories")
        for category in self.CATEGORIES.keys():
            self.filter_combo.addItem(category)
        self.filter_combo.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_combo)

        self.status_filter = QComboBox()
        self.status_filter.addItem("All Status")
        self.status_filter.addItem("Failed Only")
        self.status_filter.addItem("Warnings Only")
        self.status_filter.addItem("Passed Only")
        self.status_filter.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addStretch()

        self.fix_button = QPushButton("Apply Fixes")
        self.fix_button.setEnabled(False)
        self.fix_button.clicked.connect(self.fix_requested.emit)
        filter_layout.addWidget(self.fix_button)

        layout.addLayout(filter_layout)

        # Tree widget
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Check", "Status", "Details"])
        self.tree.setColumnWidth(0, 250)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 400)
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        layout.addWidget(self.tree)

    def _get_category(self, check_name: str) -> str:
        """Determine category for a check based on its name."""
        name_lower = check_name.lower()
        for category, keywords in self.CATEGORIES.items():
            if category == "Other":
                continue
            for keyword in keywords:
                if keyword in name_lower:
                    return category
        return "Other"

    def _get_status_icon(self, status: CheckStatus) -> str:
        """Get status icon for display."""
        if status == CheckStatus.PASS:
            return "✓"
        elif status == CheckStatus.FAIL:
            return "✗"
        elif status == CheckStatus.WARNING:
            return "⚠"
        elif status == CheckStatus.SKIPPED:
            return "○"
        return "?"

    def _get_status_color(self, status: CheckStatus) -> QColor:
        """Get color for status."""
        if status == CheckStatus.PASS:
            return QColor(0, 180, 0)
        elif status == CheckStatus.FAIL:
            return QColor(200, 0, 0)
        elif status == CheckStatus.WARNING:
            return QColor(200, 150, 0)
        elif status == CheckStatus.SKIPPED:
            return QColor(128, 128, 128)
        return QColor(0, 0, 0)

    def add_check(self, check):
        """Add a single check result to the tree."""
        self._checks.append(check)
        self._rebuild_tree()

    def set_checks(self, checks: list):
        """Set all checks and rebuild tree."""
        self._checks = checks
        self._rebuild_tree()

        # Enable fix button if there are failures
        has_failures = any(c.status == CheckStatus.FAIL for c in checks)
        self.fix_button.setEnabled(has_failures)

    def _rebuild_tree(self):
        """Rebuild tree from current checks."""
        self.tree.clear()

        # Get current filters
        category_filter = self.filter_combo.currentText()
        status_filter = self.status_filter.currentText()

        # Group checks by category
        categories = {}
        for check in self._checks:
            category = self._get_category(check.name)

            # Apply category filter
            if category_filter != "All Categories" and category != category_filter:
                continue

            # Apply status filter
            if status_filter == "Failed Only" and check.status != CheckStatus.FAIL:
                continue
            elif status_filter == "Warnings Only" and check.status != CheckStatus.WARNING:
                continue
            elif status_filter == "Passed Only" and check.status != CheckStatus.PASS:
                continue

            if category not in categories:
                categories[category] = []
            categories[category].append(check)

        # Build tree
        for category, checks in sorted(categories.items()):
            # Create category item
            cat_item = QTreeWidgetItem(self.tree)
            cat_item.setText(0, category)

            # Count statuses in category
            passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
            failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
            warnings = sum(1 for c in checks if c.status == CheckStatus.WARNING)

            status_parts = []
            if passed:
                status_parts.append(f"{passed} ✓")
            if failed:
                status_parts.append(f"{failed} ✗")
            if warnings:
                status_parts.append(f"{warnings} ⚠")
            cat_item.setText(1, " ".join(status_parts))

            # Set category color based on worst status
            if failed > 0:
                cat_item.setForeground(1, QBrush(QColor(200, 0, 0)))
            elif warnings > 0:
                cat_item.setForeground(1, QBrush(QColor(200, 150, 0)))
            else:
                cat_item.setForeground(1, QBrush(QColor(0, 180, 0)))

            cat_item.setExpanded(True)

            # Add check items
            for check in checks:
                check_item = QTreeWidgetItem(cat_item)
                check_item.setText(0, check.name)

                status_text = self._get_status_icon(check.status)
                check_item.setText(1, status_text)
                check_item.setForeground(1, QBrush(self._get_status_color(check.status)))

                # Details
                details = check.message or ""
                if check.fix_command:
                    details += f" [Fix: {check.fix_command}]"
                check_item.setText(2, details)

                # Store check object for later access
                check_item.setData(0, Qt.ItemDataRole.UserRole, check)

    def _apply_filter(self):
        """Apply current filter settings."""
        self._rebuild_tree()

    def get_failed_checks(self) -> list:
        """Get list of failed checks."""
        return [c for c in self._checks if c.status == CheckStatus.FAIL]

    def clear(self):
        """Clear all checks."""
        self._checks = []
        self.tree.clear()
        self.fix_button.setEnabled(False)
