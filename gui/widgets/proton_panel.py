"""Proton management panel."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QPushButton, QComboBox, QProgressBar,
    QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSlot

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import (
    find_proton_installations,
    fetch_ge_proton_releases,
    find_steam_root,
)
from ..workers import ProtonWorker


class ProtonPanel(QWidget):
    """Panel for managing Proton installations."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self._releases = []
        self._setup_ui()
        self._refresh_installations()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Installed Proton versions
        installed_group = QGroupBox("Installed Proton Versions")
        installed_layout = QVBoxLayout(installed_group)

        self.installed_list = QListWidget()
        self.installed_list.setMinimumHeight(200)
        installed_layout.addWidget(self.installed_list)

        # Installed list buttons
        installed_btn_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh_installations)
        installed_btn_layout.addWidget(self.refresh_btn)

        installed_btn_layout.addStretch()

        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.setEnabled(False)
        self.remove_btn.clicked.connect(self._remove_selected)
        installed_btn_layout.addWidget(self.remove_btn)

        installed_layout.addLayout(installed_btn_layout)
        layout.addWidget(installed_group)

        # Install GE-Proton section
        install_group = QGroupBox("Install GE-Proton")
        install_layout = QVBoxLayout(install_group)

        version_layout = QHBoxLayout()
        version_layout.addWidget(QLabel("Version:"))

        self.version_combo = QComboBox()
        self.version_combo.setMinimumWidth(200)
        version_layout.addWidget(self.version_combo)

        self.fetch_btn = QPushButton("Fetch Releases")
        self.fetch_btn.clicked.connect(self._fetch_releases)
        version_layout.addWidget(self.fetch_btn)

        version_layout.addStretch()

        self.install_btn = QPushButton("Install")
        self.install_btn.setEnabled(False)
        self.install_btn.clicked.connect(self._install_selected)
        version_layout.addWidget(self.install_btn)

        install_layout.addLayout(version_layout)

        # Progress section
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        install_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        install_layout.addWidget(self.progress_bar)

        layout.addWidget(install_group)

        # Check for updates section
        update_group = QGroupBox("Updates")
        update_layout = QHBoxLayout(update_group)

        self.update_status = QLabel("Click 'Check Updates' to see if a new version is available.")
        update_layout.addWidget(self.update_status)

        update_layout.addStretch()

        self.check_updates_btn = QPushButton("Check Updates")
        self.check_updates_btn.clicked.connect(self._check_updates)
        update_layout.addWidget(self.check_updates_btn)

        layout.addWidget(update_group)

        layout.addStretch()

        # Connect list selection
        self.installed_list.itemSelectionChanged.connect(self._on_selection_changed)

    def _refresh_installations(self):
        """Refresh list of installed Proton versions."""
        self.installed_list.clear()

        steam_root = find_steam_root()
        installations = find_proton_installations(steam_root)
        for install in installations:
            # Check if it's a custom installation (in compatibilitytools.d)
            is_custom = "compatibilitytools.d" in install.path
            item = QListWidgetItem(install.name)
            item.setData(Qt.ItemDataRole.UserRole, install)

            # Mark custom (removable) installations
            if is_custom:
                item.setText(f"{install.name} [Custom]")

            self.installed_list.addItem(item)

        self.remove_btn.setEnabled(False)

    def _on_selection_changed(self):
        """Handle selection change in installed list."""
        items = self.installed_list.selectedItems()
        if items:
            install = items[0].data(Qt.ItemDataRole.UserRole)
            # Only allow removing custom (GE-Proton) installations
            is_custom = "compatibilitytools.d" in install.path if install else False
            self.remove_btn.setEnabled(is_custom)
        else:
            self.remove_btn.setEnabled(False)

    def _fetch_releases(self):
        """Fetch available GE-Proton releases."""
        self.fetch_btn.setEnabled(False)
        self.fetch_btn.setText("Fetching...")

        try:
            self._releases = fetch_ge_proton_releases(limit=20)
            self.version_combo.clear()

            if self._releases:
                for release in self._releases:
                    tag = release.get('tag_name', 'Unknown')
                    self.version_combo.addItem(tag)
                self.install_btn.setEnabled(True)
            else:
                self.version_combo.addItem("No releases found")
                self.install_btn.setEnabled(False)

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to fetch releases: {e}")
        finally:
            self.fetch_btn.setEnabled(True)
            self.fetch_btn.setText("Fetch Releases")

    def _install_selected(self):
        """Install selected GE-Proton version."""
        version = self.version_combo.currentText()
        if not version or version == "No releases found":
            return

        self._start_operation("install", version)

    def _remove_selected(self):
        """Remove selected Proton installation."""
        items = self.installed_list.selectedItems()
        if not items:
            return

        install = items[0].data(Qt.ItemDataRole.UserRole)
        is_custom = "compatibilitytools.d" in install.path if install else False
        if not install or not is_custom:
            QMessageBox.warning(
                self, "Cannot Remove",
                "Only custom GE-Proton installations can be removed."
            )
            return

        confirm = QMessageBox.question(
            self, "Confirm Removal",
            f"Remove {install.name}?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm == QMessageBox.StandardButton.Yes:
            self._start_operation("remove", install.name)

    def _check_updates(self):
        """Check for GE-Proton updates."""
        self._start_operation("check_updates")

    def _start_operation(self, operation: str, version: str = ""):
        """Start a background Proton operation."""
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(self, "Busy", "An operation is already in progress.")
            return

        self._set_controls_enabled(False)
        self.progress_label.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate

        self._worker = ProtonWorker(operation, version)
        self._worker.progress.connect(self._on_progress)
        self._worker.download_progress.connect(self._on_download_progress)
        self._worker.complete.connect(self._on_complete)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _set_controls_enabled(self, enabled: bool):
        """Enable or disable controls during operation."""
        self.install_btn.setEnabled(enabled and self.version_combo.count() > 0)
        self.remove_btn.setEnabled(enabled and bool(self.installed_list.selectedItems()))
        self.fetch_btn.setEnabled(enabled)
        self.check_updates_btn.setEnabled(enabled)
        self.refresh_btn.setEnabled(enabled)

    @pyqtSlot(str)
    def _on_progress(self, message: str):
        """Handle progress update."""
        self.progress_label.setText(message)

    @pyqtSlot(int, int)
    def _on_download_progress(self, downloaded: int, total: int):
        """Handle download progress."""
        if total > 0:
            self.progress_bar.setRange(0, 100)
            percent = int(downloaded / total * 100)
            self.progress_bar.setValue(percent)
            mb_down = downloaded / (1024 * 1024)
            mb_total = total / (1024 * 1024)
            self.progress_label.setText(f"Downloading: {mb_down:.1f} / {mb_total:.1f} MB")

    @pyqtSlot(bool, str)
    def _on_complete(self, success: bool, message: str):
        """Handle operation complete."""
        self._finish_operation()

        if success:
            QMessageBox.information(self, "Complete", message)
            self._refresh_installations()
        else:
            QMessageBox.warning(self, "Notice", message)

        # Update status label for update checks
        if self._worker and self._worker.operation == "check_updates":
            self.update_status.setText(message)

    @pyqtSlot(str)
    def _on_error(self, error: str):
        """Handle operation error."""
        self._finish_operation()
        QMessageBox.critical(self, "Error", error)

    def _finish_operation(self):
        """Clean up after operation."""
        self._set_controls_enabled(True)
        self.progress_label.setVisible(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self._worker = None
