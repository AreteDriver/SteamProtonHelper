"""Fix confirmation dialog."""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QPushButton, QMessageBox, QGroupBox
)
from PyQt6.QtCore import Qt

import subprocess
import shutil


class FixDialog(QDialog):
    """Dialog showing fixes to apply and confirming with user."""

    def __init__(self, checks: list, distro: str, pkg_manager: str, parent=None):
        super().__init__(parent)
        self.checks = checks
        self.distro = distro
        self.pkg_manager = pkg_manager

        self.setWindowTitle("Apply Fixes")
        self.setMinimumSize(600, 400)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Header
        header = QLabel(f"The following fixes will be applied ({self.distro}, {self.pkg_manager}):")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        # Collect packages and commands
        packages = set()
        manual_commands = []

        for check in self.checks:
            if check.fix_packages:
                packages.update(check.fix_packages)
            if check.fix_command:
                # Check if it's a package install command or manual command
                cmd = check.fix_command
                if any(pm in cmd for pm in ['apt', 'dnf', 'pacman', 'zypper']):
                    # Extract packages from install command
                    parts = cmd.split()
                    if 'install' in parts:
                        idx = parts.index('install')
                        packages.update(parts[idx+1:])
                else:
                    manual_commands.append(cmd)

        # Package install section
        if packages:
            pkg_group = QGroupBox("Packages to Install")
            pkg_layout = QVBoxLayout(pkg_group)

            pkg_list = QTextEdit()
            pkg_list.setReadOnly(True)
            pkg_list.setPlainText("\n".join(sorted(packages)))
            pkg_list.setMaximumHeight(100)
            pkg_layout.addWidget(pkg_list)

            # Generate install command
            if self.pkg_manager == "apt":
                self.install_cmd = f"sudo apt install -y {' '.join(sorted(packages))}"
            elif self.pkg_manager == "dnf":
                self.install_cmd = f"sudo dnf install -y {' '.join(sorted(packages))}"
            elif self.pkg_manager == "pacman":
                self.install_cmd = f"sudo pacman -S --noconfirm {' '.join(sorted(packages))}"
            elif self.pkg_manager == "zypper":
                self.install_cmd = f"sudo zypper install -y {' '.join(sorted(packages))}"
            else:
                self.install_cmd = f"# Install: {' '.join(sorted(packages))}"

            cmd_label = QLabel(f"Command: {self.install_cmd}")
            cmd_label.setWordWrap(True)
            cmd_label.setStyleSheet("font-family: monospace; background: #f0f0f0; padding: 5px;")
            pkg_layout.addWidget(cmd_label)

            layout.addWidget(pkg_group)
        else:
            self.install_cmd = None

        # Manual commands section
        if manual_commands:
            manual_group = QGroupBox("Manual Commands Required")
            manual_layout = QVBoxLayout(manual_group)

            manual_text = QTextEdit()
            manual_text.setReadOnly(True)
            manual_text.setPlainText("\n".join(manual_commands))
            manual_text.setMaximumHeight(100)
            manual_layout.addWidget(manual_text)

            note = QLabel("These commands require manual execution:")
            note.setStyleSheet("color: #cc6600;")
            manual_layout.addWidget(note)

            layout.addWidget(manual_group)

        self.manual_commands = manual_commands

        # Warning
        warning = QLabel("⚠ This will run commands with elevated privileges (sudo).")
        warning.setStyleSheet("color: #cc6600; font-weight: bold;")
        layout.addWidget(warning)

        layout.addStretch()

        # Buttons
        button_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy Commands")
        self.copy_btn.clicked.connect(self._copy_commands)
        button_layout.addWidget(self.copy_btn)

        button_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        self.apply_btn = QPushButton("Apply Fixes")
        self.apply_btn.setDefault(True)
        self.apply_btn.clicked.connect(self._apply_fixes)
        if not self.install_cmd and not self.manual_commands:
            self.apply_btn.setEnabled(False)
        button_layout.addWidget(self.apply_btn)

        layout.addLayout(button_layout)

    def _copy_commands(self):
        """Copy all commands to clipboard."""
        from PyQt6.QtWidgets import QApplication

        commands = []
        if self.install_cmd:
            commands.append(self.install_cmd)
        commands.extend(self.manual_commands)

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(commands))

        QMessageBox.information(self, "Copied", "Commands copied to clipboard.")

    def _apply_fixes(self):
        """Apply package installation fixes."""
        if not self.install_cmd:
            self.accept()
            return

        # Try to find a terminal or pkexec
        pkexec = shutil.which("pkexec")
        terminals = ["gnome-terminal", "konsole", "xfce4-terminal", "xterm"]

        if pkexec:
            # Use pkexec for graphical sudo
            try:
                # Remove 'sudo' from command since pkexec provides elevation
                cmd = self.install_cmd.replace("sudo ", "")
                result = subprocess.run(
                    [pkexec] + cmd.split(),
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    QMessageBox.information(
                        self,
                        "Success",
                        "Packages installed successfully.\n\nPlease refresh checks."
                    )
                    self.accept()
                else:
                    QMessageBox.warning(
                        self,
                        "Installation Failed",
                        f"Error: {result.stderr or result.stdout}"
                    )
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
        else:
            # Fallback: show command to copy
            QMessageBox.information(
                self,
                "Manual Installation Required",
                f"Please run this command in a terminal:\n\n{self.install_cmd}"
            )
            self.accept()
