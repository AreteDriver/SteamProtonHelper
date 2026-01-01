"""Main application window."""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget,
    QToolBar, QStatusBar, QMessageBox, QFileDialog,
    QApplication
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QAction, QKeySequence

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from steam_proton_helper import DependencyCheck, CheckStatus

from .widgets import ChecksPanel, SummaryPanel, ProtonDBPanel, ProtonPanel, FixDialog
from .workers import CheckWorker


class MainWindow(QMainWindow):
    """Main application window with tabbed interface."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steam Proton Helper")
        self.setMinimumSize(900, 600)

        self._check_worker = None
        self._distro = ""
        self._pkg_manager = ""
        self._all_checks = []

        self._setup_ui()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()

        # Auto-run checks on startup
        self._run_checks()

    def _setup_ui(self):
        """Set up the main UI."""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(5, 5, 5, 5)

        # Summary panel at top
        self.summary_panel = SummaryPanel()
        layout.addWidget(self.summary_panel)

        # Tab widget
        self.tabs = QTabWidget()

        # Tab 0: System Checks
        self.checks_panel = ChecksPanel()
        self.checks_panel.fix_requested.connect(self._show_fix_dialog)
        self.tabs.addTab(self.checks_panel, "System Checks")

        # Tab 1: Proton Management
        self.proton_panel = ProtonPanel()
        self.tabs.addTab(self.proton_panel, "Proton Management")

        # Tab 2: ProtonDB Lookup
        self.protondb_panel = ProtonDBPanel()
        self.tabs.addTab(self.protondb_panel, "ProtonDB Lookup")

        layout.addWidget(self.tabs)

    def _setup_menu(self):
        """Set up menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        export_action = QAction("&Export Report...", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence("Ctrl+Q"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self):
        """Set up toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.refresh_action = QAction("Refresh Checks", self)
        self.refresh_action.setShortcut(QKeySequence("F5"))
        self.refresh_action.triggered.connect(self._run_checks)
        toolbar.addAction(self.refresh_action)

        self.fix_action = QAction("Apply Fixes", self)
        self.fix_action.setEnabled(False)
        self.fix_action.triggered.connect(self._show_fix_dialog)
        toolbar.addAction(self.fix_action)

    def _setup_statusbar(self):
        """Set up status bar."""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")

    def _run_checks(self):
        """Run dependency checks in background."""
        if self._check_worker and self._check_worker.isRunning():
            return

        # Reset UI
        self.summary_panel.reset()
        self.checks_panel.clear()
        self.refresh_action.setEnabled(False)
        self.fix_action.setEnabled(False)
        self.statusbar.showMessage("Running checks...")

        # Start worker
        self._check_worker = CheckWorker()
        self._check_worker.progress.connect(self._on_check_progress)
        self._check_worker.check_complete.connect(self._on_check_complete)
        self._check_worker.all_complete.connect(self._on_all_checks_complete)
        self._check_worker.error.connect(self._on_check_error)
        self._check_worker.start()

    @pyqtSlot(str, int)
    def _on_check_progress(self, message: str, percent: int):
        """Handle check progress update."""
        self.summary_panel.show_progress(message, percent)

    @pyqtSlot(object)
    def _on_check_complete(self, check: DependencyCheck):
        """Handle individual check complete."""
        self.checks_panel.add_check(check)

    @pyqtSlot(list, str, str)
    def _on_all_checks_complete(self, checks: list, distro: str, pkg_manager: str):
        """Handle all checks complete."""
        self._all_checks = checks
        self._distro = distro
        self._pkg_manager = pkg_manager

        self.summary_panel.hide_progress()
        self.summary_panel.update_summary(checks)
        self.checks_panel.set_checks(checks)

        self.refresh_action.setEnabled(True)

        # Enable fix button if there are failures
        has_failures = any(c.status == CheckStatus.FAIL for c in checks)
        self.fix_action.setEnabled(has_failures)

        passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
        failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        warnings = sum(1 for c in checks if c.status == CheckStatus.WARNING)
        self.statusbar.showMessage(
            f"Checks complete: {passed} passed, {failed} failed, {warnings} warnings"
        )

    @pyqtSlot(str)
    def _on_check_error(self, error: str):
        """Handle check error."""
        self.summary_panel.hide_progress()
        self.refresh_action.setEnabled(True)
        self.statusbar.showMessage(f"Error: {error}")
        QMessageBox.critical(self, "Check Error", error)

    def _show_fix_dialog(self):
        """Show dialog to apply fixes."""
        failed_checks = self.checks_panel.get_failed_checks()
        if not failed_checks:
            QMessageBox.information(
                self, "No Fixes Needed",
                "There are no failed checks to fix."
            )
            return

        dialog = FixDialog(failed_checks, self._distro, self._pkg_manager, self)
        if dialog.exec():
            # Re-run checks after applying fixes
            self._run_checks()

    def _export_report(self):
        """Export check results to JSON file."""
        if not self._all_checks:
            QMessageBox.information(
                self, "No Data",
                "Run checks first before exporting."
            )
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            "steam-proton-helper-report.json",
            "JSON Files (*.json)"
        )

        if not filename:
            return

        report = {
            "distro": self._distro,
            "package_manager": self._pkg_manager,
            "checks": []
        }

        for check in self._all_checks:
            report["checks"].append({
                "name": check.name,
                "status": check.status.value,
                "message": check.message,
                "fix_command": check.fix_command,
                "fix_packages": check.fix_packages,
            })

        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            self.statusbar.showMessage(f"Report exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self, "About Steam Proton Helper",
            "<h3>Steam Proton Helper</h3>"
            "<p>Version 2.0</p>"
            "<p>A tool to help configure Linux for Steam gaming with Proton.</p>"
            "<p>Features:</p>"
            "<ul>"
            "<li>System dependency checking</li>"
            "<li>GE-Proton management</li>"
            "<li>ProtonDB game lookup</li>"
            "</ul>"
            "<p><a href='https://github.com/AreteDriver/SteamProtonHelper'>GitHub</a></p>"
        )

    def closeEvent(self, event):
        """Handle window close."""
        if self._check_worker and self._check_worker.isRunning():
            self._check_worker.cancel()
            self._check_worker.wait(1000)
        event.accept()
