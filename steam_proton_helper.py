#!/usr/bin/env python3
"""
Steam Proton Helper - A non-destructive checker for Steam/Proton readiness on Linux.

This tool checks dependencies, validates installations, and reports system readiness
for Steam gaming. It does NOT install packages by default.
"""

__version__ = "1.1.0"
__author__ = "SteamProtonHelper Contributors"

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Tuple, Optional, Any


# -----------------------------------------------------------------------------
# Enums and Data Classes
# -----------------------------------------------------------------------------

class CheckStatus(Enum):
    """Status of a dependency check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARN"
    SKIPPED = "SKIP"


class SteamVariant(Enum):
    """Steam installation variant."""
    NATIVE = "native"
    FLATPAK = "flatpak"
    SNAP = "snap"
    NONE = "none"


@dataclass
class DependencyCheck:
    """Result of a dependency check."""
    name: str
    status: CheckStatus
    message: str
    category: str = "General"
    fix_command: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "category": self.category,
            "fix_command": self.fix_command,
            "details": self.details,
        }


@dataclass
class ProtonInstall:
    """Information about a Proton installation."""
    name: str
    path: str
    has_executable: bool
    has_toolmanifest: bool
    has_version: bool


# -----------------------------------------------------------------------------
# Color Output
# -----------------------------------------------------------------------------

class Color:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

    _enabled = True

    @classmethod
    def disable(cls) -> None:
        """Disable all color output."""
        cls.GREEN = ''
        cls.RED = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.END = ''
        cls._enabled = False

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if colors are enabled."""
        return cls._enabled


# -----------------------------------------------------------------------------
# Verbose Logger
# -----------------------------------------------------------------------------

class VerboseLogger:
    """Logger that only outputs when verbose mode is enabled."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def log(self, message: str) -> None:
        """Log a verbose message."""
        if self.enabled:
            print(f"{Color.DIM}[DEBUG] {message}{Color.END}")


# Global logger instance
verbose_log = VerboseLogger()


# -----------------------------------------------------------------------------
# VDF Parser (Minimal implementation for libraryfolders.vdf)
# -----------------------------------------------------------------------------

def parse_libraryfolders_vdf(filepath: str) -> List[str]:
    """
    Parse Steam's libraryfolders.vdf to extract library paths.

    This is a minimal VDF parser that extracts quoted strings under "path" keys.
    Valve's VDF format is similar to JSON but uses a different syntax.

    Args:
        filepath: Path to libraryfolders.vdf

    Returns:
        List of library paths found in the file.
    """
    paths: List[str] = []
    verbose_log.log(f"Parsing VDF file: {filepath}")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Match "path" followed by whitespace and a quoted string
        # Pattern handles both: "path"		"/path/to/lib" and "path" "/path"
        pattern = r'"path"\s+"([^"]+)"'
        matches = re.findall(pattern, content, re.IGNORECASE)

        for match in matches:
            expanded = os.path.expanduser(match)
            resolved = os.path.realpath(expanded)
            if os.path.isdir(resolved):
                paths.append(resolved)
                verbose_log.log(f"  Found library path: {resolved}")
            else:
                verbose_log.log(f"  Path not a directory, skipping: {resolved}")

    except FileNotFoundError:
        verbose_log.log(f"  VDF file not found: {filepath}")
    except PermissionError:
        verbose_log.log(f"  Permission denied reading: {filepath}")
    except Exception as e:
        verbose_log.log(f"  Error parsing VDF: {e}")

    return paths


# -----------------------------------------------------------------------------
# Distribution Detection
# -----------------------------------------------------------------------------

class DistroDetector:
    """Detect Linux distribution and package manager."""

    @staticmethod
    def detect_distro() -> Tuple[str, str]:
        """
        Detect the Linux distribution.

        Returns:
            Tuple of (distro_name, package_manager)
        """
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    distro_info = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            distro_info[key] = value.strip('"')

                    distro_id = distro_info.get('ID', '').lower()
                    distro_like = distro_info.get('ID_LIKE', '').lower()
                    distro_name = distro_info.get('PRETTY_NAME', distro_id)

                    # Determine package manager
                    if distro_id in ['ubuntu', 'debian', 'mint', 'pop', 'linuxmint', 'elementary'] \
                            or 'debian' in distro_like or 'ubuntu' in distro_like:
                        return (distro_name, 'apt')
                    elif distro_id in ['fedora', 'rhel', 'centos', 'rocky', 'alma'] \
                            or 'fedora' in distro_like or 'rhel' in distro_like:
                        return (distro_name, 'dnf')
                    elif distro_id in ['arch', 'manjaro', 'endeavouros', 'garuda', 'artix'] \
                            or 'arch' in distro_like:
                        return (distro_name, 'pacman')
                    elif distro_id in ['opensuse', 'suse', 'opensuse-leap', 'opensuse-tumbleweed']:
                        return (distro_name, 'zypper')

            # Fallback to checking for package managers
            for pm in ['apt', 'dnf', 'pacman', 'zypper']:
                if shutil.which(pm):
                    return ('unknown', pm)

        except Exception as e:
            verbose_log.log(f"Error detecting distro: {e}")

        return ('unknown', 'unknown')


# -----------------------------------------------------------------------------
# Steam Detection
# -----------------------------------------------------------------------------

def detect_steam_variant() -> Tuple[SteamVariant, str]:
    """
    Detect which Steam variant is installed.

    Returns:
        Tuple of (SteamVariant, description_message)
    """
    variants_found: List[Tuple[SteamVariant, str]] = []

    # Check native Steam
    if shutil.which('steam'):
        verbose_log.log("Found 'steam' in PATH (native)")
        variants_found.append((SteamVariant.NATIVE, "Native Steam in PATH"))

    # Check Flatpak Steam
    try:
        result = subprocess.run(
            ['flatpak', 'info', 'com.valvesoftware.Steam'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            verbose_log.log("Found Flatpak Steam")
            variants_found.append((SteamVariant.FLATPAK, "Flatpak (com.valvesoftware.Steam)"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        verbose_log.log("Flatpak not available or timed out")
    except Exception as e:
        verbose_log.log(f"Error checking Flatpak Steam: {e}")

    # Check Snap Steam (best-effort)
    try:
        result = subprocess.run(
            ['snap', 'list', 'steam'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and 'steam' in result.stdout.lower():
            verbose_log.log("Found Snap Steam")
            variants_found.append((SteamVariant.SNAP, "Snap package"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        verbose_log.log("Snap not available or timed out")
    except Exception as e:
        verbose_log.log(f"Error checking Snap Steam: {e}")

    if not variants_found:
        return (SteamVariant.NONE, "Steam not detected")

    # Return first found (prefer native > flatpak > snap)
    primary = variants_found[0]
    if len(variants_found) > 1:
        others = ", ".join(v[1] for v in variants_found[1:])
        return (primary[0], f"{primary[1]} (also found: {others})")
    return primary


def find_steam_root() -> Optional[str]:
    """
    Find the active Steam root directory.

    Checks common Steam installation paths and resolves symlinks.

    Returns:
        Path to Steam root, or None if not found.
    """
    candidates = [
        os.path.expanduser('~/.local/share/Steam'),
        os.path.expanduser('~/.steam/root'),
        os.path.expanduser('~/.steam/steam'),
        # Flatpak location
        os.path.expanduser('~/.var/app/com.valvesoftware.Steam/.local/share/Steam'),
        os.path.expanduser('~/.var/app/com.valvesoftware.Steam/.steam/steam'),
    ]

    for candidate in candidates:
        verbose_log.log(f"Checking Steam root candidate: {candidate}")
        try:
            resolved = os.path.realpath(candidate)
            if not os.path.isdir(resolved):
                verbose_log.log(f"  Not a directory: {resolved}")
                continue

            # Check for steamapps directory or libraryfolders.vdf
            steamapps = os.path.join(resolved, 'steamapps')
            vdf_path = os.path.join(steamapps, 'libraryfolders.vdf')

            if os.path.isdir(steamapps):
                verbose_log.log(f"  Found steamapps at: {steamapps}")
                return resolved
            if os.path.isfile(vdf_path):
                verbose_log.log(f"  Found libraryfolders.vdf at: {vdf_path}")
                return resolved

        except (PermissionError, OSError) as e:
            verbose_log.log(f"  Error accessing {candidate}: {e}")

    return None


def get_library_paths(steam_root: Optional[str]) -> List[str]:
    """
    Get all Steam library paths.

    Parses libraryfolders.vdf and includes the root library.

    Args:
        steam_root: Path to Steam root directory.

    Returns:
        List of library paths.
    """
    libraries: List[str] = []

    if not steam_root:
        return libraries

    # The root itself is always a library
    libraries.append(steam_root)

    # Parse libraryfolders.vdf
    vdf_path = os.path.join(steam_root, 'steamapps', 'libraryfolders.vdf')
    if os.path.isfile(vdf_path):
        parsed = parse_libraryfolders_vdf(vdf_path)
        for lib in parsed:
            if lib not in libraries:
                libraries.append(lib)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for lib in libraries:
        resolved = os.path.realpath(lib)
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)

    return unique


def find_proton_installations(steam_root: Optional[str]) -> List[ProtonInstall]:
    """
    Find all Proton installations across Steam libraries.

    Searches:
    - <library>/steamapps/common/Proton*
    - <root>/compatibilitytools.d/*Proton* (GE-Proton, etc.)
    - <library>/steamapps/compatibilitytools.d/*Proton*

    Args:
        steam_root: Path to Steam root directory.

    Returns:
        List of ProtonInstall objects.
    """
    protons: List[ProtonInstall] = []

    if not steam_root:
        return protons

    libraries = get_library_paths(steam_root)
    verbose_log.log(f"Searching for Proton in {len(libraries)} library path(s)")

    search_patterns: List[Tuple[str, str]] = []

    for lib in libraries:
        # Official Proton in steamapps/common
        search_patterns.append((os.path.join(lib, 'steamapps', 'common'), 'Proton*'))
        search_patterns.append((os.path.join(lib, 'steamapps', 'common'), 'proton*'))

        # Custom Proton in compatibilitytools.d
        search_patterns.append((os.path.join(lib, 'compatibilitytools.d'), '*Proton*'))
        search_patterns.append((os.path.join(lib, 'compatibilitytools.d'), '*proton*'))
        search_patterns.append((os.path.join(lib, 'steamapps', 'compatibilitytools.d'), '*Proton*'))
        search_patterns.append((os.path.join(lib, 'steamapps', 'compatibilitytools.d'), '*proton*'))

    # Also check root's compatibilitytools.d
    root_compat = os.path.join(steam_root, 'compatibilitytools.d')
    if root_compat not in [p[0] for p in search_patterns]:
        search_patterns.append((root_compat, '*Proton*'))
        search_patterns.append((root_compat, '*proton*'))

    # Also check ~/.steam/root/compatibilitytools.d (common for GE-Proton)
    home_compat = os.path.expanduser('~/.steam/root/compatibilitytools.d')
    if os.path.isdir(home_compat):
        search_patterns.append((home_compat, '*Proton*'))
        search_patterns.append((home_compat, '*proton*'))
        search_patterns.append((home_compat, 'GE-Proton*'))

    seen_paths = set()

    for base_dir, pattern in search_patterns:
        if not os.path.isdir(base_dir):
            continue

        verbose_log.log(f"  Searching: {base_dir}/{pattern}")

        try:
            for entry in os.listdir(base_dir):
                entry_lower = entry.lower()
                pattern_lower = pattern.lower().replace('*', '')

                # Simple glob matching
                if pattern_lower in entry_lower or 'proton' in entry_lower:
                    full_path = os.path.join(base_dir, entry)
                    resolved = os.path.realpath(full_path)

                    if resolved in seen_paths:
                        continue
                    if not os.path.isdir(resolved):
                        continue

                    seen_paths.add(resolved)

                    # Check for Proton markers
                    has_exec = os.path.isfile(os.path.join(resolved, 'proton'))
                    has_manifest = os.path.isfile(os.path.join(resolved, 'toolmanifest.vdf'))
                    has_version = os.path.isfile(os.path.join(resolved, 'version'))

                    if has_exec or has_manifest or has_version:
                        protons.append(ProtonInstall(
                            name=entry,
                            path=resolved,
                            has_executable=has_exec,
                            has_toolmanifest=has_manifest,
                            has_version=has_version
                        ))
                        verbose_log.log(f"    Found Proton: {entry}")

        except (PermissionError, OSError) as e:
            verbose_log.log(f"    Error listing {base_dir}: {e}")

    return protons


# -----------------------------------------------------------------------------
# Dependency Checker
# -----------------------------------------------------------------------------

class DependencyChecker:
    """Check for Steam and Proton dependencies."""

    def __init__(self, distro: str, package_manager: str):
        self.distro = distro
        self.package_manager = package_manager
        self.checks: List[DependencyCheck] = []

    def run_command(
        self,
        cmd: List[str],
        timeout: int = 30
    ) -> Tuple[int, str, str]:
        """
        Run a shell command and return (exit_code, stdout, stderr).

        Args:
            cmd: Command and arguments as list.
            timeout: Timeout in seconds.

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        verbose_log.log(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (1, '', 'Command timed out')
        except FileNotFoundError:
            return (127, '', f'Command not found: {cmd[0]}')
        except Exception as e:
            return (1, '', str(e))

    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH."""
        return shutil.which(command) is not None

    def check_package_installed(self, package: str) -> bool:
        """
        Check if a package is installed using the system package manager.

        Args:
            package: Package name to check.

        Returns:
            True if installed, False otherwise.
        """
        if self.package_manager == 'apt':
            # Use dpkg-query for accurate status check
            code, stdout, _ = self.run_command([
                'dpkg-query', '-W', '-f=${Status}', package
            ])
            return code == 0 and 'install ok installed' in stdout

        elif self.package_manager == 'dnf':
            code, _, _ = self.run_command(['rpm', '-q', package])
            return code == 0

        elif self.package_manager == 'pacman':
            code, _, _ = self.run_command(['pacman', '-Q', package])
            return code == 0

        elif self.package_manager == 'zypper':
            code, _, _ = self.run_command(['rpm', '-q', package])
            return code == 0

        return False

    def check_multilib_enabled(self) -> Tuple[bool, str]:
        """
        Check if 32-bit/multilib support is enabled.

        Returns:
            Tuple of (is_enabled, message)
        """
        if self.package_manager == 'apt':
            code, stdout, _ = self.run_command(['dpkg', '--print-foreign-architectures'])
            if 'i386' in stdout:
                return (True, "i386 architecture enabled")
            return (False, "i386 architecture not enabled (run: sudo dpkg --add-architecture i386)")

        elif self.package_manager == 'pacman':
            # Check /etc/pacman.conf for [multilib] not commented
            try:
                with open('/etc/pacman.conf', 'r') as f:
                    content = f.read()
                # Look for [multilib] that's not commented
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped == '[multilib]':
                        # Check if the Include line follows
                        if i + 1 < len(lines):
                            next_line = lines[i + 1].strip()
                            if next_line.startswith('Include') and not next_line.startswith('#'):
                                return (True, "[multilib] repository enabled")
                        return (True, "[multilib] section found")
                return (False, "[multilib] not enabled in /etc/pacman.conf")
            except Exception as e:
                verbose_log.log(f"Error reading pacman.conf: {e}")
                return (False, "Could not read /etc/pacman.conf")

        elif self.package_manager == 'dnf':
            # DNF handles multilib automatically, just check for .i686 packages
            return (True, "DNF supports multilib automatically")

        return (True, "Assuming multilib support available")

    def _get_install_command(self, package: str) -> str:
        """Get the install command for a package based on package manager."""
        commands = {
            'apt': f"sudo apt update && sudo apt install -y {package}",
            'dnf': f"sudo dnf install -y {package}",
            'pacman': f"sudo pacman -S --noconfirm {package}",
            'zypper': f"sudo zypper install -y {package}",
        }
        return commands.get(self.package_manager, f"Please install {package} manually")

    # -------------------------------------------------------------------------
    # Individual Checks
    # -------------------------------------------------------------------------

    def check_system(self) -> List[DependencyCheck]:
        """Check system information."""
        checks = []

        # Linux distribution
        checks.append(DependencyCheck(
            name="Linux Distribution",
            status=CheckStatus.PASS,
            message=f"{self.distro}",
            category="System",
            details=f"Package manager: {self.package_manager}"
        ))

        # Architecture
        arch = platform.machine()
        if arch == 'x86_64':
            checks.append(DependencyCheck(
                name="64-bit System",
                status=CheckStatus.PASS,
                message="x86_64 architecture",
                category="System"
            ))
        else:
            checks.append(DependencyCheck(
                name="System Architecture",
                status=CheckStatus.WARNING,
                message=f"{arch} (Steam primarily supports x86_64)",
                category="System"
            ))

        return checks

    def check_steam(self) -> List[DependencyCheck]:
        """Check Steam installation."""
        checks = []

        variant, message = detect_steam_variant()

        if variant == SteamVariant.NONE:
            fix_cmd = self._get_install_command('steam')
            checks.append(DependencyCheck(
                name="Steam Client",
                status=CheckStatus.FAIL,
                message="Steam is not installed",
                category="Steam",
                fix_command=fix_cmd
            ))
        else:
            checks.append(DependencyCheck(
                name="Steam Client",
                status=CheckStatus.PASS,
                message=f"Installed: {message}",
                category="Steam"
            ))

        # Check Steam root directory
        steam_root = find_steam_root()
        if steam_root:
            checks.append(DependencyCheck(
                name="Steam Root",
                status=CheckStatus.PASS,
                message=steam_root,
                category="Steam"
            ))

            # Check library folders
            libraries = get_library_paths(steam_root)
            if len(libraries) > 1:
                checks.append(DependencyCheck(
                    name="Steam Libraries",
                    status=CheckStatus.PASS,
                    message=f"{len(libraries)} library folder(s) found",
                    category="Steam",
                    details="\n".join(libraries)
                ))
        else:
            if variant != SteamVariant.NONE:
                checks.append(DependencyCheck(
                    name="Steam Root",
                    status=CheckStatus.WARNING,
                    message="Steam root directory not found (Steam may not have been run yet)",
                    category="Steam"
                ))

        return checks

    def check_proton(self) -> List[DependencyCheck]:
        """Check Proton installations."""
        checks = []

        steam_root = find_steam_root()
        protons = find_proton_installations(steam_root)

        if protons:
            # List found Proton versions
            names = [p.name for p in protons]
            checks.append(DependencyCheck(
                name="Proton",
                status=CheckStatus.PASS,
                message=f"Found {len(protons)} installation(s)",
                category="Proton",
                details="\n".join(f"  - {p.name}: {p.path}" for p in protons)
            ))
        else:
            checks.append(DependencyCheck(
                name="Proton",
                status=CheckStatus.WARNING,
                message="No Proton installations found",
                category="Proton",
                fix_command="Install Proton from Steam: Settings → Compatibility → Enable Steam Play"
            ))

        return checks

    def check_graphics(self) -> List[DependencyCheck]:
        """Check graphics/Vulkan support."""
        checks = []

        # Check Vulkan
        if self.check_command_exists('vulkaninfo'):
            # Run vulkaninfo (without --summary as per spec)
            code, stdout, stderr = self.run_command(['vulkaninfo'])
            if code == 0:
                checks.append(DependencyCheck(
                    name="Vulkan Support",
                    status=CheckStatus.PASS,
                    message="Vulkan is available",
                    category="Graphics"
                ))
            else:
                checks.append(DependencyCheck(
                    name="Vulkan Support",
                    status=CheckStatus.FAIL,
                    message="vulkaninfo failed - Vulkan may not be properly configured",
                    category="Graphics",
                    fix_command="Check Vulkan ICD installation, GPU drivers, and 32-bit Vulkan libs",
                    details=f"Error: {stderr[:200] if stderr else 'Unknown error'}"
                ))
        else:
            vulkan_pkg = {
                'apt': 'vulkan-tools',
                'dnf': 'vulkan-tools',
                'pacman': 'vulkan-tools',
            }.get(self.package_manager, 'vulkan-tools')

            checks.append(DependencyCheck(
                name="Vulkan Tools",
                status=CheckStatus.FAIL,
                message="vulkaninfo not found",
                category="Graphics",
                fix_command=self._get_install_command(vulkan_pkg)
            ))

        # Check Mesa/OpenGL
        if self.check_command_exists('glxinfo'):
            code, stdout, stderr = self.run_command(['glxinfo', '-B'])
            if code == 0:
                checks.append(DependencyCheck(
                    name="Mesa/OpenGL",
                    status=CheckStatus.PASS,
                    message="OpenGL support available",
                    category="Graphics"
                ))
            else:
                checks.append(DependencyCheck(
                    name="Mesa/OpenGL",
                    status=CheckStatus.WARNING,
                    message="glxinfo returned error (may need display)",
                    category="Graphics",
                    details=f"This may be normal in headless/SSH sessions"
                ))
        else:
            checks.append(DependencyCheck(
                name="Mesa/OpenGL",
                status=CheckStatus.WARNING,
                message="glxinfo not installed (optional)",
                category="Graphics",
                fix_command=self._get_install_command('mesa-utils')
            ))

        return checks

    def check_32bit_support(self) -> List[DependencyCheck]:
        """Check 32-bit/multilib support and packages."""
        checks = []

        # Check if multilib is enabled
        enabled, message = self.check_multilib_enabled()
        if enabled:
            checks.append(DependencyCheck(
                name="Multilib/32-bit",
                status=CheckStatus.PASS,
                message=message,
                category="32-bit"
            ))
        else:
            checks.append(DependencyCheck(
                name="Multilib/32-bit",
                status=CheckStatus.FAIL,
                message=message,
                category="32-bit"
            ))

        # Check required 32-bit packages per distro
        packages_to_check: Dict[str, List[str]] = {
            'apt': [
                'libc6-i386',
                'libstdc++6:i386',
                'libvulkan1:i386',
                'mesa-vulkan-drivers:i386',
            ],
            'pacman': [
                'lib32-glibc',
                'lib32-gcc-libs',
                'lib32-vulkan-icd-loader',
                'lib32-mesa',
            ],
            'dnf': [
                'glibc.i686',
                'libgcc.i686',
                'libstdc++.i686',
                'vulkan-loader.i686',
            ],
        }

        if self.package_manager in packages_to_check:
            for pkg in packages_to_check[self.package_manager]:
                if self.check_package_installed(pkg):
                    checks.append(DependencyCheck(
                        name=pkg,
                        status=CheckStatus.PASS,
                        message="Installed",
                        category="32-bit"
                    ))
                else:
                    # For dnf vulkan-loader, be less strict since package name may vary
                    if self.package_manager == 'dnf' and 'vulkan' in pkg:
                        checks.append(DependencyCheck(
                            name=pkg,
                            status=CheckStatus.WARNING,
                            message="Not found (package name may vary)",
                            category="32-bit",
                            fix_command=self._get_install_command(pkg)
                        ))
                    else:
                        checks.append(DependencyCheck(
                            name=pkg,
                            status=CheckStatus.FAIL,
                            message="Not installed",
                            category="32-bit",
                            fix_command=self._get_install_command(pkg)
                        ))

        return checks

    def run_all_checks(self) -> List[DependencyCheck]:
        """Run all dependency checks."""
        all_checks: List[DependencyCheck] = []

        all_checks.extend(self.check_system())
        all_checks.extend(self.check_steam())
        all_checks.extend(self.check_proton())
        all_checks.extend(self.check_graphics())
        all_checks.extend(self.check_32bit_support())

        return all_checks


# -----------------------------------------------------------------------------
# Output Formatting
# -----------------------------------------------------------------------------

def get_status_symbol(status: CheckStatus) -> str:
    """Get the display symbol for a check status."""
    symbols = {
        CheckStatus.PASS: "✓",
        CheckStatus.FAIL: "✗",
        CheckStatus.WARNING: "⚠",
        CheckStatus.SKIPPED: "○",
    }
    return symbols.get(status, "?")


def get_status_color(status: CheckStatus) -> str:
    """Get the color for a check status."""
    colors = {
        CheckStatus.PASS: Color.GREEN,
        CheckStatus.FAIL: Color.RED,
        CheckStatus.WARNING: Color.YELLOW,
        CheckStatus.SKIPPED: Color.BLUE,
    }
    return colors.get(status, '')


def print_header() -> None:
    """Print the application header with correct box drawing."""
    print()
    print(f"{Color.BOLD}{Color.CYAN}╔══════════════════════════════════════════╗{Color.END}")
    print(f"{Color.BOLD}{Color.CYAN}║   Steam + Proton Helper for Linux        ║{Color.END}")
    print(f"{Color.BOLD}{Color.CYAN}╚══════════════════════════════════════════╝{Color.END}")
    print()


def print_checks_by_category(checks: List[DependencyCheck], verbose: bool = False) -> None:
    """Print checks grouped by category."""
    # Group by category
    categories: Dict[str, List[DependencyCheck]] = {}
    for check in checks:
        cat = check.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(check)

    # Define category order
    category_order = ["System", "Steam", "Proton", "Graphics", "32-bit"]

    for category in category_order:
        if category not in categories:
            continue

        print(f"\n{Color.BOLD}── {category} ──{Color.END}")

        for check in categories[category]:
            color = get_status_color(check.status)
            symbol = get_status_symbol(check.status)

            print(f"  {color}{symbol}{Color.END} {Color.BOLD}{check.name}{Color.END}: {check.message}")

            if check.fix_command:
                print(f"      {Color.CYAN}Fix:{Color.END} {check.fix_command}")

            if verbose and check.details:
                for line in check.details.split('\n'):
                    print(f"      {Color.DIM}{line}{Color.END}")

    # Print any remaining categories
    for category, cat_checks in categories.items():
        if category in category_order:
            continue

        print(f"\n{Color.BOLD}── {category} ──{Color.END}")
        for check in cat_checks:
            color = get_status_color(check.status)
            symbol = get_status_symbol(check.status)
            print(f"  {color}{symbol}{Color.END} {Color.BOLD}{check.name}{Color.END}: {check.message}")


def print_summary(checks: List[DependencyCheck]) -> None:
    """Print summary of check results."""
    passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
    failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
    warnings = sum(1 for c in checks if c.status == CheckStatus.WARNING)
    skipped = sum(1 for c in checks if c.status == CheckStatus.SKIPPED)

    print(f"\n{Color.BOLD}{'─' * 44}{Color.END}")
    print(f"{Color.BOLD}Summary{Color.END}")
    print(f"  {Color.GREEN}Passed:{Color.END}   {passed}")
    print(f"  {Color.RED}Failed:{Color.END}   {failed}")
    print(f"  {Color.YELLOW}Warnings:{Color.END} {warnings}")
    if skipped > 0:
        print(f"  {Color.BLUE}Skipped:{Color.END}  {skipped}")

    print()
    if failed == 0 and warnings == 0:
        print(f"{Color.GREEN}{Color.BOLD}✓ Your system is ready for Steam gaming!{Color.END}")
    elif failed == 0:
        print(f"{Color.YELLOW}{Color.BOLD}⚠ Your system is mostly ready. Review warnings above.{Color.END}")
    else:
        print(f"{Color.RED}{Color.BOLD}✗ Some checks failed. Install missing dependencies.{Color.END}")


def print_tips() -> None:
    """Print helpful tips."""
    print(f"\n{Color.BOLD}Tips:{Color.END}")
    print(f"  • Enable Proton in Steam: Settings → Compatibility → Enable Steam Play")
    print(f"  • Keep graphics drivers updated for best performance")
    print(f"  • Check game compatibility at protondb.com")
    print()


def output_json(checks: List[DependencyCheck], distro: str, package_manager: str) -> None:
    """Output results as JSON."""
    steam_variant, steam_msg = detect_steam_variant()
    steam_root = find_steam_root()
    protons = find_proton_installations(steam_root)

    result = {
        "system": {
            "distro": distro,
            "package_manager": package_manager,
            "arch": platform.machine(),
        },
        "steam": {
            "variant": steam_variant.value,
            "message": steam_msg,
            "root": steam_root,
            "libraries": get_library_paths(steam_root) if steam_root else [],
        },
        "proton": {
            "found": len(protons) > 0,
            "installations": [
                {
                    "name": p.name,
                    "path": p.path,
                    "has_executable": p.has_executable,
                    "has_toolmanifest": p.has_toolmanifest,
                    "has_version": p.has_version,
                }
                for p in protons
            ],
        },
        "checks": [c.to_dict() for c in checks],
        "summary": {
            "passed": sum(1 for c in checks if c.status == CheckStatus.PASS),
            "failed": sum(1 for c in checks if c.status == CheckStatus.FAIL),
            "warnings": sum(1 for c in checks if c.status == CheckStatus.WARNING),
            "skipped": sum(1 for c in checks if c.status == CheckStatus.SKIPPED),
        },
    }

    print(json.dumps(result, indent=2))


# -----------------------------------------------------------------------------
# Fix Script Generation
# -----------------------------------------------------------------------------

def generate_fix_script(
    checks: List[DependencyCheck],
    distro: str,
    package_manager: str
) -> str:
    """
    Generate a shell script containing commands to fix failed checks.

    Args:
        checks: List of dependency check results.
        distro: Linux distribution name.
        package_manager: Package manager (apt, dnf, pacman, etc.)

    Returns:
        Shell script as a string.
    """
    lines: List[str] = []

    # Header
    lines.append("#!/bin/bash")
    lines.append("# Steam Proton Helper - Fix Script")
    lines.append(f"# Generated for: {distro}")
    lines.append(f"# Package manager: {package_manager}")
    lines.append("#")
    lines.append("# Review this script before running!")
    lines.append("# Run with: bash fix-steam-proton.sh")
    lines.append("")
    lines.append("set -e  # Exit on error")
    lines.append("")

    # Collect fix commands from failed/warning checks
    fix_commands: List[Tuple[str, str]] = []
    for check in checks:
        if check.status in (CheckStatus.FAIL, CheckStatus.WARNING) and check.fix_command:
            fix_commands.append((check.name, check.fix_command))

    if not fix_commands:
        lines.append("echo 'No fixes needed - all checks passed!'")
        lines.append("exit 0")
    else:
        lines.append(f"echo 'Steam Proton Helper - Applying {len(fix_commands)} fix(es)'")
        lines.append("echo ''")
        lines.append("")

        # Group commands that can be combined (same package manager commands)
        apt_packages: List[str] = []
        dnf_packages: List[str] = []
        pacman_packages: List[str] = []
        other_commands: List[Tuple[str, str]] = []

        for name, cmd in fix_commands:
            # Try to extract package names from install commands
            if 'apt install' in cmd or 'apt-get install' in cmd:
                # Extract packages after 'install'
                parts = cmd.split('install')
                if len(parts) > 1:
                    pkgs = parts[1].replace('-y', '').strip().split()
                    apt_packages.extend(pkgs)
                else:
                    other_commands.append((name, cmd))
            elif 'dnf install' in cmd:
                parts = cmd.split('install')
                if len(parts) > 1:
                    pkgs = parts[1].replace('-y', '').strip().split()
                    dnf_packages.extend(pkgs)
                else:
                    other_commands.append((name, cmd))
            elif 'pacman -S' in cmd:
                parts = cmd.split('-S')
                if len(parts) > 1:
                    pkgs = parts[1].replace('--noconfirm', '').strip().split()
                    pacman_packages.extend(pkgs)
                else:
                    other_commands.append((name, cmd))
            else:
                other_commands.append((name, cmd))

        # Output combined package install commands
        if apt_packages:
            unique_pkgs = sorted(set(apt_packages))
            lines.append("# Install missing packages (apt)")
            lines.append(f"echo 'Installing: {' '.join(unique_pkgs)}'")
            lines.append(f"sudo apt update && sudo apt install -y {' '.join(unique_pkgs)}")
            lines.append("")

        if dnf_packages:
            unique_pkgs = sorted(set(dnf_packages))
            lines.append("# Install missing packages (dnf)")
            lines.append(f"echo 'Installing: {' '.join(unique_pkgs)}'")
            lines.append(f"sudo dnf install -y {' '.join(unique_pkgs)}")
            lines.append("")

        if pacman_packages:
            unique_pkgs = sorted(set(pacman_packages))
            lines.append("# Install missing packages (pacman)")
            lines.append(f"echo 'Installing: {' '.join(unique_pkgs)}'")
            lines.append(f"sudo pacman -S --noconfirm {' '.join(unique_pkgs)}")
            lines.append("")

        # Output other commands
        for name, cmd in other_commands:
            lines.append(f"# Fix: {name}")
            lines.append(f"echo 'Fixing: {name}'")
            lines.append(cmd)
            lines.append("")

        lines.append("echo ''")
        lines.append("echo 'Done! Run steam-proton-helper again to verify fixes.'")

    return "\n".join(lines)


def output_fix_script(
    checks: List[DependencyCheck],
    distro: str,
    package_manager: str,
    output_file: str
) -> bool:
    """
    Output the fix script to a file or stdout.

    Args:
        checks: List of dependency check results.
        distro: Linux distribution name.
        package_manager: Package manager.
        output_file: Filename or "-" for stdout.

    Returns:
        True if script was written, False if no fixes needed.
    """
    script = generate_fix_script(checks, distro, package_manager)

    # Count actual fixes
    fix_count = sum(
        1 for c in checks
        if c.status in (CheckStatus.FAIL, CheckStatus.WARNING) and c.fix_command
    )

    if output_file == "-":
        print(script)
    else:
        with open(output_file, 'w') as f:
            f.write(script)
        os.chmod(output_file, 0o755)
        print(f"Fix script written to: {output_file}")
        print(f"Contains {fix_count} fix command(s)")
        if fix_count > 0:
            print(f"\nReview and run with: bash {output_file}")

    return fix_count > 0


# -----------------------------------------------------------------------------
# Apply / Dry-Run Implementation
# -----------------------------------------------------------------------------

def collect_fix_actions(
    checks: List[DependencyCheck],
    package_manager: str
) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Collect fix actions from failed/warning checks.

    Args:
        checks: List of dependency check results.
        package_manager: Package manager (apt, dnf, pacman).

    Returns:
        Tuple of (packages_to_install, other_commands)
        where other_commands is list of (name, command) tuples.
    """
    packages: List[str] = []
    other_commands: List[Tuple[str, str]] = []

    for check in checks:
        if check.status not in (CheckStatus.FAIL, CheckStatus.WARNING):
            continue
        if not check.fix_command:
            continue

        cmd = check.fix_command

        # Extract packages from install commands
        if package_manager == 'apt' and ('apt install' in cmd or 'apt-get install' in cmd):
            parts = cmd.split('install')
            if len(parts) > 1:
                pkgs = parts[1].replace('-y', '').strip().split()
                packages.extend(pkgs)
            else:
                other_commands.append((check.name, cmd))

        elif package_manager == 'dnf' and 'dnf install' in cmd:
            parts = cmd.split('install')
            if len(parts) > 1:
                pkgs = parts[1].replace('-y', '').strip().split()
                packages.extend(pkgs)
            else:
                other_commands.append((check.name, cmd))

        elif package_manager == 'pacman' and 'pacman -S' in cmd:
            parts = cmd.split('-S')
            if len(parts) > 1:
                pkgs = parts[1].replace('--noconfirm', '').strip().split()
                packages.extend(pkgs)
            else:
                other_commands.append((check.name, cmd))

        else:
            other_commands.append((check.name, cmd))

    # Deduplicate packages
    unique_packages = sorted(set(packages))

    return (unique_packages, other_commands)


def show_dry_run(
    checks: List[DependencyCheck],
    package_manager: str
) -> int:
    """
    Show what --apply would do without executing.

    Args:
        checks: List of dependency check results.
        package_manager: Package manager.

    Returns:
        Number of actions that would be taken.
    """
    packages, other_commands = collect_fix_actions(checks, package_manager)

    if not packages and not other_commands:
        print(f"{Color.GREEN}No fixes needed - all checks passed!{Color.END}")
        return 0

    print(f"{Color.BOLD}Dry run - the following actions would be taken:{Color.END}")
    print()

    action_count = 0

    if packages:
        print(f"{Color.CYAN}Packages to install:{Color.END}")
        for pkg in packages:
            print(f"  • {pkg}")
            action_count += 1

        # Show the command that would be run
        if package_manager == 'apt':
            cmd = f"sudo apt update && sudo apt install -y {' '.join(packages)}"
        elif package_manager == 'dnf':
            cmd = f"sudo dnf install -y {' '.join(packages)}"
        elif package_manager == 'pacman':
            cmd = f"sudo pacman -S --noconfirm {' '.join(packages)}"
        else:
            cmd = f"Install: {' '.join(packages)}"

        print()
        print(f"{Color.DIM}Command: {cmd}{Color.END}")
        print()

    if other_commands:
        print(f"{Color.CYAN}Other actions:{Color.END}")
        for name, cmd in other_commands:
            print(f"  • {name}")
            print(f"    {Color.DIM}{cmd}{Color.END}")
            action_count += 1
        print()

    print(f"{Color.BOLD}Total: {action_count} action(s){Color.END}")
    print()
    print(f"Run with {Color.CYAN}--apply{Color.END} to execute these fixes.")

    return action_count


def apply_fixes(
    checks: List[DependencyCheck],
    package_manager: str,
    skip_confirm: bool = False
) -> Tuple[bool, str]:
    """
    Apply fixes by installing missing packages.

    Args:
        checks: List of dependency check results.
        package_manager: Package manager.
        skip_confirm: Skip confirmation prompt if True.

    Returns:
        Tuple of (success, message)
    """
    packages, other_commands = collect_fix_actions(checks, package_manager)

    if not packages and not other_commands:
        return (True, "No fixes needed - all checks passed!")

    # Show what will be done
    print(f"{Color.BOLD}The following fixes will be applied:{Color.END}")
    print()

    if packages:
        print(f"{Color.CYAN}Packages to install ({len(packages)}):{Color.END}")
        for pkg in packages:
            print(f"  • {pkg}")
        print()

    if other_commands:
        print(f"{Color.YELLOW}Manual actions required ({len(other_commands)}):{Color.END}")
        for name, cmd in other_commands:
            print(f"  • {name}: {cmd}")
        print()

    # Only install packages automatically, not other commands
    if not packages:
        print(f"{Color.YELLOW}No packages to install automatically.{Color.END}")
        print("Please run the manual actions listed above.")
        return (True, "No automatic fixes available")

    # Confirmation prompt
    if not skip_confirm:
        print(f"{Color.BOLD}This will run sudo to install packages.{Color.END}")
        try:
            response = input(f"Continue? [y/N] ").strip().lower()
            if response not in ('y', 'yes'):
                return (False, "Cancelled by user")
        except (EOFError, KeyboardInterrupt):
            print()
            return (False, "Cancelled by user")

    # Build and execute the install command
    print()
    print(f"{Color.BOLD}Installing packages...{Color.END}")
    print()

    if package_manager == 'apt':
        # Update first, then install
        update_cmd = ['sudo', 'apt', 'update']
        install_cmd = ['sudo', 'apt', 'install', '-y'] + packages
    elif package_manager == 'dnf':
        update_cmd = None
        install_cmd = ['sudo', 'dnf', 'install', '-y'] + packages
    elif package_manager == 'pacman':
        update_cmd = ['sudo', 'pacman', '-Sy']
        install_cmd = ['sudo', 'pacman', '-S', '--noconfirm'] + packages
    else:
        return (False, f"Unsupported package manager: {package_manager}")

    try:
        # Run update if needed
        if update_cmd:
            print(f"{Color.DIM}$ {' '.join(update_cmd)}{Color.END}")
            result = subprocess.run(update_cmd, check=False)
            if result.returncode != 0:
                return (False, "Package list update failed")

        # Run install
        print(f"{Color.DIM}$ {' '.join(install_cmd)}{Color.END}")
        result = subprocess.run(install_cmd, check=False)

        if result.returncode == 0:
            print()
            print(f"{Color.GREEN}✓ Packages installed successfully!{Color.END}")

            if other_commands:
                print()
                print(f"{Color.YELLOW}Note: The following manual actions are still required:{Color.END}")
                for name, cmd in other_commands:
                    print(f"  • {name}: {cmd}")

            print()
            print(f"Run {Color.CYAN}steam-proton-helper{Color.END} again to verify all fixes.")
            return (True, "Packages installed successfully")
        else:
            return (False, f"Installation failed with exit code {result.returncode}")

    except FileNotFoundError:
        return (False, f"Package manager '{package_manager}' not found")
    except Exception as e:
        return (False, f"Error during installation: {e}")


# -----------------------------------------------------------------------------
# Main Application
# -----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Steam Proton Helper - Check system readiness for Steam gaming on Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                  Run all checks with colored output
  %(prog)s --json           Output results as JSON
  %(prog)s --fix            Print fix script to stdout
  %(prog)s --fix fix.sh     Write fix script to file
  %(prog)s --dry-run        Show what --apply would install
  %(prog)s --apply          Install missing packages (prompts for confirmation)
  %(prog)s --apply -y       Install without confirmation prompt
  %(prog)s --no-color       Disable colored output
  %(prog)s --verbose        Show debug information

Note: Use --dry-run to preview before --apply. Requires sudo for installation.
"""
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as machine-readable JSON'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable ANSI color codes in output'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose/debug output including paths tried'
    )

    parser.add_argument(
        '--fix',
        nargs='?',
        const='-',
        metavar='FILE',
        help='Generate a shell script with fix commands. Use "-" or omit for stdout, or specify a filename.'
    )

    parser.add_argument(
        '--apply',
        action='store_true',
        help='Auto-install missing packages (requires sudo, prompts for confirmation)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what --apply would install without executing'
    )

    parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Skip confirmation prompt when using --apply'
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Configure based on arguments
    if args.no_color or not sys.stdout.isatty():
        Color.disable()

    global verbose_log
    verbose_log = VerboseLogger(enabled=args.verbose)

    try:
        # Detect distro
        distro, package_manager = DistroDetector.detect_distro()
        verbose_log.log(f"Detected distro: {distro}, package manager: {package_manager}")

        # Run checks
        checker = DependencyChecker(distro, package_manager)
        checks = checker.run_all_checks()

        # Output results
        if args.fix is not None:
            # Generate fix script
            output_fix_script(checks, distro, package_manager, args.fix)
        elif args.dry_run:
            # Show what --apply would do
            print_header()
            show_dry_run(checks, package_manager)
        elif args.apply:
            # Apply fixes
            print_header()
            success, message = apply_fixes(checks, package_manager, skip_confirm=args.yes)
            if not success:
                print(f"{Color.RED}✗ {message}{Color.END}")
                return 1
            print(f"{Color.GREEN}{message}{Color.END}")
        elif args.json:
            output_json(checks, distro, package_manager)
        else:
            print_header()
            print(f"{Color.BOLD}Checking Steam and Proton dependencies...{Color.END}")
            print_checks_by_category(checks, verbose=args.verbose)
            print_summary(checks)
            print_tips()

        # Return exit code based on failures
        failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        return 1 if failed > 0 else 0

    except KeyboardInterrupt:
        if not args.json:
            print(f"\n{Color.YELLOW}Interrupted by user{Color.END}")
        return 130
    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\n{Color.RED}Error: {e}{Color.END}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
