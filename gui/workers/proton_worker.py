"""Background worker for Proton operations."""

from PyQt6.QtCore import QThread, pyqtSignal

import sys
import os
import urllib.request
import tarfile
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import (
    fetch_ge_proton_releases,
    find_steam_root,
    check_ge_proton_updates,
)


class ProtonWorker(QThread):
    """Background thread for Proton installation operations."""

    # Signals
    progress = pyqtSignal(str)  # Status message
    download_progress = pyqtSignal(int, int)  # (downloaded, total)
    complete = pyqtSignal(bool, str)  # (success, message)
    error = pyqtSignal(str)

    def __init__(self, operation: str, version: str = "", force: bool = False, parent=None):
        super().__init__(parent)
        self.operation = operation  # "install", "remove", "check_updates"
        self.version = version
        self.force = force
        self._is_cancelled = False

    def cancel(self):
        """Request cancellation."""
        self._is_cancelled = True

    def run(self):
        """Execute the Proton operation."""
        try:
            if self.operation == "install":
                self._install_proton()
            elif self.operation == "remove":
                self._remove_proton()
            elif self.operation == "check_updates":
                self._check_updates()
            else:
                self.error.emit(f"Unknown operation: {self.operation}")
        except Exception as e:
            self.error.emit(str(e))

    def _install_proton(self):
        """Download and install GE-Proton."""
        self.progress.emit("Fetching release information...")

        # Get releases
        releases = fetch_ge_proton_releases(limit=20)
        if not releases:
            self.error.emit("Failed to fetch GE-Proton releases")
            return

        # Find target version
        if self.version.lower() == "latest":
            release = releases[0]
        else:
            release = next((r for r in releases if r['tag_name'] == self.version), None)
            if not release:
                self.error.emit(f"Version {self.version} not found")
                return

        tag = release['tag_name']
        self.progress.emit(f"Installing {tag}...")

        # Find download URL
        download_url = None
        for asset in release.get('assets', []):
            name = asset.get('name', '')
            if name.endswith('.tar.gz') and 'GE-Proton' in name:
                download_url = asset.get('browser_download_url')
                break

        if not download_url:
            self.error.emit("No download URL found for this release")
            return

        # Get Steam compatibility tools directory
        steam_root = find_steam_root()
        if not steam_root:
            self.error.emit("Could not find Steam installation")
            return

        compat_dir = os.path.join(steam_root, "compatibilitytools.d")
        os.makedirs(compat_dir, exist_ok=True)

        # Check if already installed
        target_dir = os.path.join(compat_dir, tag)
        if os.path.exists(target_dir) and not self.force:
            self.complete.emit(True, f"{tag} is already installed")
            return

        if self._is_cancelled:
            return

        # Download
        self.progress.emit(f"Downloading {tag}...")
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            self._download_file(download_url, tmp_path)

            if self._is_cancelled:
                os.unlink(tmp_path)
                return

            # Extract
            self.progress.emit(f"Extracting {tag}...")
            with tarfile.open(tmp_path, 'r:gz') as tar:
                tar.extractall(compat_dir)

            self.complete.emit(True, f"Successfully installed {tag}")

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _download_file(self, url: str, dest: str):
        """Download a file with progress reporting."""
        req = urllib.request.Request(url, headers={'User-Agent': 'steam-proton-helper-gui/2.0'})

        with urllib.request.urlopen(req, timeout=60) as response:
            total = int(response.headers.get('Content-Length', 0))
            downloaded = 0

            with open(dest, 'wb') as f:
                while not self._is_cancelled:
                    chunk = response.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    self.download_progress.emit(downloaded, total)

    def _remove_proton(self):
        """Remove a custom Proton installation."""
        steam_root = find_steam_root()
        if not steam_root:
            self.error.emit("Could not find Steam installation")
            return

        compat_dir = os.path.join(steam_root, "compatibilitytools.d")
        target_dir = os.path.join(compat_dir, self.version)

        if not os.path.exists(target_dir):
            self.error.emit(f"{self.version} is not installed")
            return

        self.progress.emit(f"Removing {self.version}...")
        shutil.rmtree(target_dir)
        self.complete.emit(True, f"Successfully removed {self.version}")

    def _check_updates(self):
        """Check for GE-Proton updates."""
        self.progress.emit("Checking for updates...")

        result = check_ge_proton_updates()
        if result:
            installed, latest = result
            if installed != latest:
                self.complete.emit(True, f"Update available: {latest} (installed: {installed})")
            else:
                self.complete.emit(True, f"Already up to date: {installed}")
        else:
            self.complete.emit(False, "No GE-Proton installed or could not check updates")
