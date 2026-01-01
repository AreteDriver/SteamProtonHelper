"""Background worker for running dependency checks."""

from PyQt6.QtCore import QThread, pyqtSignal

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from steam_proton_helper import (
    DependencyChecker,
    DependencyCheck,
    DistroDetector,
)


class CheckWorker(QThread):
    """Background thread for running all dependency checks."""

    # Signals
    progress = pyqtSignal(str, int)  # (message, percent)
    check_complete = pyqtSignal(object)  # DependencyCheck
    all_complete = pyqtSignal(list, str, str)  # (checks, distro, pkg_manager)
    error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._is_cancelled = False

    def cancel(self):
        """Request cancellation of the check process."""
        self._is_cancelled = True

    def run(self):
        """Run all dependency checks in background."""
        try:
            # Detect system
            self.progress.emit("Detecting system...", 0)
            distro, pkg_manager = DistroDetector.detect_distro()

            if self._is_cancelled:
                return

            # Create checker
            self.progress.emit("Initializing checker...", 5)
            checker = DependencyChecker(distro, pkg_manager)

            if self._is_cancelled:
                return

            # Define check phases with weights
            check_phases = [
                ("System", 10),
                ("Steam", 20),
                ("Proton", 30),
                ("Graphics", 45),
                ("32-bit Support", 55),
                ("Gaming Tools", 65),
                ("Wine", 75),
                ("DXVK/VKD3D", 85),
                ("Steam Runtime", 92),
                ("Extra Tools", 98),
            ]

            # Run all checks
            self.progress.emit("Running checks...", 10)
            all_checks = checker.run_all_checks()

            # Emit each check individually for real-time updates
            for check in all_checks:
                if self._is_cancelled:
                    return
                self.check_complete.emit(check)

            self.progress.emit("Complete", 100)
            self.all_complete.emit(all_checks, distro, pkg_manager)

        except Exception as e:
            self.error.emit(str(e))
