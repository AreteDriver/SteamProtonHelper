#!/usr/bin/env python3
"""
Steam Proton Helper - A non-destructive checker for Steam/Proton readiness on Linux.

This tool checks dependencies, validates installations, and reports system readiness
for Steam gaming. It does NOT install packages by default.
"""

__version__ = "2.3.3"
__author__ = "SteamProtonHelper Contributors"

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
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


@dataclass
class GameLaunchProfile:
    """Per-game launch configuration."""
    app_id: str
    name: str
    proton_version: Optional[str] = None
    launch_options: Optional[str] = None
    env_vars: Optional[Dict[str, str]] = None
    mangohud: bool = False
    gamemode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "app_id": self.app_id,
            "name": self.name,
            "proton_version": self.proton_version,
            "launch_options": self.launch_options,
            "env_vars": self.env_vars or {},
            "mangohud": self.mangohud,
            "gamemode": self.gamemode,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GameLaunchProfile":
        """Create from dictionary."""
        return cls(
            app_id=data["app_id"],
            name=data.get("name", ""),
            proton_version=data.get("proton_version"),
            launch_options=data.get("launch_options"),
            env_vars=data.get("env_vars"),
            mangohud=data.get("mangohud", False),
            gamemode=data.get("gamemode", False),
        )


@dataclass
class InstalledGame:
    """Information about an installed Steam game."""
    app_id: str
    name: str
    install_dir: str
    size_bytes: int
    proton_version: Optional[str] = None
    last_played: Optional[str] = None
    playtime_hours: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "app_id": self.app_id,
            "name": self.name,
            "install_dir": self.install_dir,
            "size_bytes": self.size_bytes,
            "size_human": self._human_size(self.size_bytes),
            "proton_version": self.proton_version,
            "last_played": self.last_played,
            "playtime_hours": self.playtime_hours,
        }

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"


@dataclass
class ShaderCacheInfo:
    """Information about a game's shader cache."""
    app_id: str
    name: str
    cache_path: str
    size_bytes: int
    file_count: int
    last_modified: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "app_id": self.app_id,
            "name": self.name,
            "cache_path": self.cache_path,
            "size_bytes": self.size_bytes,
            "size_human": self._human_size(self.size_bytes),
            "file_count": self.file_count,
            "last_modified": self.last_modified,
        }

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"


@dataclass
class CompatdataInfo:
    """Information about a game's Wine prefix (compatdata)."""
    app_id: str
    name: str
    path: str
    size_bytes: int
    last_modified: Optional[str] = None
    proton_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "app_id": self.app_id,
            "name": self.name,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "size_human": self._human_size(self.size_bytes),
            "last_modified": self.last_modified,
            "proton_version": self.proton_version,
        }

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"


@dataclass
class PerformanceToolStatus:
    """Status of a performance tool."""
    name: str
    installed: bool
    active: bool
    version: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "name": self.name,
            "installed": self.installed,
            "active": self.active,
            "version": self.version,
            "details": self.details,
        }


@dataclass
class LogEntry:
    """A parsed log entry from Steam/Proton logs."""
    timestamp: Optional[str]
    level: str  # INFO, WARNING, ERROR
    source: str  # steam, proton, wine
    message: str
    game_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "game_id": self.game_id,
        }


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
        self.steam_root: Optional[str] = None

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
        self.steam_root = steam_root  # Store for other checks
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
                    details="This may be normal in headless/SSH sessions"
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

    def check_gaming_tools(self) -> List[DependencyCheck]:
        """Check optional gaming performance tools (GameMode, MangoHud)."""
        checks = []

        # Check GameMode
        if self.check_command_exists('gamemoded') or self.check_command_exists('gamemode'):
            # Try to check if gamemoded is running or can be started
            code, stdout, stderr = self.run_command(['gamemoded', '--status'])
            if code == 0:
                checks.append(DependencyCheck(
                    name="GameMode",
                    status=CheckStatus.PASS,
                    message="GameMode daemon available",
                    category="Gaming Tools",
                    details="Use 'gamemoderun %command%' in Steam launch options"
                ))
            else:
                checks.append(DependencyCheck(
                    name="GameMode",
                    status=CheckStatus.PASS,
                    message="GameMode installed",
                    category="Gaming Tools",
                    details="Use 'gamemoderun %command%' in Steam launch options"
                ))
        else:
            gamemode_pkg = {
                'apt': 'gamemode',
                'dnf': 'gamemode',
                'pacman': 'gamemode',
            }.get(self.package_manager, 'gamemode')

            checks.append(DependencyCheck(
                name="GameMode",
                status=CheckStatus.WARNING,
                message="GameMode not installed (optional performance optimizer)",
                category="Gaming Tools",
                fix_command=self._get_install_command(gamemode_pkg),
                details="GameMode optimizes CPU governor, I/O priority, and more during gaming"
            ))

        # Check MangoHud
        if self.check_command_exists('mangohud'):
            checks.append(DependencyCheck(
                name="MangoHud",
                status=CheckStatus.PASS,
                message="MangoHud overlay available",
                category="Gaming Tools",
                details="Use 'mangohud %command%' or MANGOHUD=1 in Steam launch options"
            ))
        else:
            mangohud_pkg = {
                'apt': 'mangohud',
                'dnf': 'mangohud',
                'pacman': 'mangohud',
            }.get(self.package_manager, 'mangohud')

            checks.append(DependencyCheck(
                name="MangoHud",
                status=CheckStatus.WARNING,
                message="MangoHud not installed (optional FPS/performance overlay)",
                category="Gaming Tools",
                fix_command=self._get_install_command(mangohud_pkg),
                details="MangoHud shows FPS, CPU/GPU stats, and frame timing"
            ))

        return checks

    def check_wine(self) -> List[DependencyCheck]:
        """Check Wine installation (used by some games and tools)."""
        checks = []

        # Check for Wine
        wine_found = False
        wine_version = None

        if self.check_command_exists('wine'):
            wine_found = True
            code, stdout, stderr = self.run_command(['wine', '--version'])
            if code == 0 and stdout:
                wine_version = stdout.strip()

        if self.check_command_exists('wine64'):
            wine_found = True
            if not wine_version:
                code, stdout, stderr = self.run_command(['wine64', '--version'])
                if code == 0 and stdout:
                    wine_version = stdout.strip()

        if wine_found:
            checks.append(DependencyCheck(
                name="Wine",
                status=CheckStatus.PASS,
                message=f"Wine installed ({wine_version})" if wine_version else "Wine installed",
                category="Wine",
                details="Wine is used by some games and compatibility tools"
            ))
        else:
            wine_pkg = {
                'apt': 'wine',
                'dnf': 'wine',
                'pacman': 'wine',
            }.get(self.package_manager, 'wine')

            checks.append(DependencyCheck(
                name="Wine",
                status=CheckStatus.WARNING,
                message="Wine not installed (optional, Proton includes its own)",
                category="Wine",
                fix_command=self._get_install_command(wine_pkg),
                details="Most Steam games use Proton's bundled Wine; standalone Wine is optional"
            ))

        # Check for Winetricks
        if self.check_command_exists('winetricks'):
            checks.append(DependencyCheck(
                name="Winetricks",
                status=CheckStatus.PASS,
                message="Winetricks available",
                category="Wine",
                details="Useful for installing Windows components in Wine prefixes"
            ))
        else:
            checks.append(DependencyCheck(
                name="Winetricks",
                status=CheckStatus.WARNING,
                message="Winetricks not installed (optional helper tool)",
                category="Wine",
                fix_command=self._get_install_command('winetricks'),
                details="Winetricks helps install Windows DLLs and components"
            ))

        return checks

    def check_dxvk_vkd3d(self) -> List[DependencyCheck]:
        """Check DXVK and VKD3D-Proton availability."""
        checks = []

        # Note: DXVK and VKD3D are bundled with Proton, so these are informational
        # We check for standalone installations which some users prefer

        # Check for standalone DXVK
        dxvk_paths = [
            os.path.expanduser('~/.local/share/dxvk'),
            '/usr/share/dxvk',
            os.path.expanduser('~/.steam/root/compatibilitytools.d'),
        ]

        dxvk_found = False
        for path in dxvk_paths:
            if os.path.isdir(path):
                # Look for DXVK DLLs
                for root, dirs, files in os.walk(path):
                    if any(f.startswith('d3d') and f.endswith('.dll') for f in files):
                        dxvk_found = True
                        break
                if dxvk_found:
                    break

        if dxvk_found:
            checks.append(DependencyCheck(
                name="DXVK",
                status=CheckStatus.PASS,
                message="Standalone DXVK installation found",
                category="Compatibility",
                details="DXVK translates D3D9/10/11 to Vulkan"
            ))
        else:
            checks.append(DependencyCheck(
                name="DXVK",
                status=CheckStatus.PASS,
                message="Using Proton's bundled DXVK (recommended)",
                category="Compatibility",
                details="Proton includes DXVK; standalone installation is optional"
            ))

        # Check for VKD3D-Proton (DirectX 12 to Vulkan)
        vkd3d_paths = [
            os.path.expanduser('~/.local/share/vkd3d-proton'),
            '/usr/share/vkd3d-proton',
        ]

        vkd3d_found = False
        for path in vkd3d_paths:
            if os.path.isdir(path):
                vkd3d_found = True
                break

        if vkd3d_found:
            checks.append(DependencyCheck(
                name="VKD3D-Proton",
                status=CheckStatus.PASS,
                message="Standalone VKD3D-Proton found",
                category="Compatibility",
                details="VKD3D-Proton translates DirectX 12 to Vulkan"
            ))
        else:
            checks.append(DependencyCheck(
                name="VKD3D-Proton",
                status=CheckStatus.PASS,
                message="Using Proton's bundled VKD3D (recommended)",
                category="Compatibility",
                details="Proton includes VKD3D-Proton; standalone installation is optional"
            ))

        return checks

    def check_steam_runtime(self) -> List[DependencyCheck]:
        """Check Steam Runtime and Pressure Vessel container."""
        checks = []

        # Check for Steam Runtime (soldier, sniper, etc.)
        runtime_paths = []
        if self.steam_root:
            runtime_paths.extend([
                os.path.join(self.steam_root, 'ubuntu12_32', 'steam-runtime'),
                os.path.join(self.steam_root, 'steamapps', 'common', 'SteamLinuxRuntime_soldier'),
                os.path.join(self.steam_root, 'steamapps', 'common', 'SteamLinuxRuntime_sniper'),
            ])

        runtime_found = None
        for path in runtime_paths:
            if os.path.isdir(path):
                if 'sniper' in path.lower():
                    runtime_found = 'sniper'
                elif 'soldier' in path.lower():
                    runtime_found = 'soldier'
                else:
                    runtime_found = 'legacy'
                break

        if runtime_found:
            runtime_names = {
                'sniper': 'Steam Linux Runtime 3.0 (sniper)',
                'soldier': 'Steam Linux Runtime 2.0 (soldier)',
                'legacy': 'Steam Runtime (legacy)',
            }
            checks.append(DependencyCheck(
                name="Steam Runtime",
                status=CheckStatus.PASS,
                message=f"{runtime_names.get(runtime_found, 'Found')}",
                category="Runtime",
                details="Container runtime for consistent game execution"
            ))
        else:
            checks.append(DependencyCheck(
                name="Steam Runtime",
                status=CheckStatus.WARNING,
                message="Steam Runtime not found (may be downloaded on first game launch)",
                category="Runtime",
                details="Steam will download the runtime when needed"
            ))

        # Check for Pressure Vessel (container tool)
        pv_paths = []
        if self.steam_root:
            pv_paths.extend([
                os.path.join(self.steam_root, 'steamapps', 'common', 'SteamLinuxRuntime_soldier', 'pressure-vessel'),
                os.path.join(self.steam_root, 'steamapps', 'common', 'SteamLinuxRuntime_sniper', 'pressure-vessel'),
            ])

        pv_found = False
        for path in pv_paths:
            if os.path.isdir(path):
                pv_found = True
                break

        if pv_found:
            checks.append(DependencyCheck(
                name="Pressure Vessel",
                status=CheckStatus.PASS,
                message="Container tool available",
                category="Runtime",
                details="Used by Steam Runtime to isolate games from host system"
            ))
        else:
            checks.append(DependencyCheck(
                name="Pressure Vessel",
                status=CheckStatus.PASS,
                message="Will be installed with Steam Runtime",
                category="Runtime",
                details="Bundled with Steam Linux Runtime"
            ))

        return checks

    def check_extra_tools(self) -> List[DependencyCheck]:
        """Check optional gaming enhancement tools."""
        checks = []

        # Check vkBasalt (post-processing for Vulkan)
        vkbasalt_found = False
        vkbasalt_paths = [
            '/usr/lib/x86_64-linux-gnu/libvkbasalt.so',
            '/usr/lib64/libvkbasalt.so',
            '/usr/lib/libvkbasalt.so',
            os.path.expanduser('~/.local/share/vkBasalt/libvkbasalt.so'),
        ]
        for path in vkbasalt_paths:
            if os.path.isfile(path):
                vkbasalt_found = True
                break

        # Also check if vkbasalt.conf exists
        if not vkbasalt_found:
            vkbasalt_found = self.check_command_exists('vkbasalt')

        if vkbasalt_found:
            checks.append(DependencyCheck(
                name="vkBasalt",
                status=CheckStatus.PASS,
                message="Post-processing layer available",
                category="Enhancements",
                details="Use ENABLE_VKBASALT=1 for CAS sharpening, FXAA, SMAA"
            ))
        else:
            vkbasalt_pkg = {
                'apt': 'vkbasalt',
                'dnf': 'vkBasalt',
                'pacman': 'vkbasalt',
            }.get(self.package_manager, 'vkbasalt')

            checks.append(DependencyCheck(
                name="vkBasalt",
                status=CheckStatus.WARNING,
                message="Not installed (optional post-processing)",
                category="Enhancements",
                fix_command=self._get_install_command(vkbasalt_pkg),
                details="Adds sharpening, FXAA, SMAA to Vulkan games"
            ))

        # Check libstrangle (FPS limiter)
        strangle_found = self.check_command_exists('strangle')
        if not strangle_found:
            strangle_paths = [
                '/usr/lib/x86_64-linux-gnu/libstrangle.so',
                '/usr/lib64/libstrangle.so',
                '/usr/lib/libstrangle.so',
            ]
            for path in strangle_paths:
                if os.path.isfile(path):
                    strangle_found = True
                    break

        if strangle_found:
            checks.append(DependencyCheck(
                name="libstrangle",
                status=CheckStatus.PASS,
                message="FPS limiter available",
                category="Enhancements",
                details="Use 'strangle 60 %command%' to limit FPS"
            ))
        else:
            checks.append(DependencyCheck(
                name="libstrangle",
                status=CheckStatus.WARNING,
                message="Not installed (optional FPS limiter)",
                category="Enhancements",
                details="Limits FPS to reduce power usage and heat"
            ))

        # Check OBS Vulkan/OpenGL capture
        obs_vkcapture_found = False
        obs_capture_paths = [
            '/usr/lib/x86_64-linux-gnu/obs-plugins/linux-vkcapture.so',
            '/usr/lib64/obs-plugins/linux-vkcapture.so',
            '/usr/lib/obs-plugins/linux-vkcapture.so',
        ]
        for path in obs_capture_paths:
            if os.path.isfile(path):
                obs_vkcapture_found = True
                break

        if not obs_vkcapture_found:
            obs_vkcapture_found = self.check_command_exists('obs-vkcapture')

        if obs_vkcapture_found:
            checks.append(DependencyCheck(
                name="OBS Game Capture",
                status=CheckStatus.PASS,
                message="Vulkan/OpenGL capture available",
                category="Enhancements",
                details="Use 'obs-vkcapture %command%' for OBS game capture"
            ))
        else:
            checks.append(DependencyCheck(
                name="OBS Game Capture",
                status=CheckStatus.WARNING,
                message="Not installed (optional for streaming/recording)",
                category="Enhancements",
                details="Enables efficient game capture in OBS Studio"
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
        all_checks.extend(self.check_gaming_tools())
        all_checks.extend(self.check_wine())
        all_checks.extend(self.check_dxvk_vkd3d())
        all_checks.extend(self.check_steam_runtime())
        all_checks.extend(self.check_extra_tools())

        return all_checks


# -----------------------------------------------------------------------------
# ProtonDB Integration
# -----------------------------------------------------------------------------

@dataclass
class ProtonDBInfo:
    """ProtonDB game compatibility information."""
    app_id: str
    tier: str
    confidence: str
    score: float
    total_reports: int
    trending_tier: Optional[str] = None
    best_reported_tier: Optional[str] = None


@dataclass
class SteamApp:
    """Steam application info."""
    appid: int
    name: str


def search_steam_games(query: str, limit: int = 10) -> List[SteamApp]:
    """
    Search for Steam games by name using the Steam Store API.

    Args:
        query: Game name to search for.
        limit: Maximum number of results to return.

    Returns:
        List of matching SteamApp objects, sorted by relevance.
    """
    import urllib.request
    import urllib.error
    import urllib.parse

    # Use Steam store search API
    encoded_query = urllib.parse.quote(query)
    url = f"https://store.steampowered.com/api/storesearch/?term={encoded_query}&l=english&cc=US"

    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            items = data.get('items', [])

            # Filter to only include apps (not DLC, packages, etc.)
            results = []
            for item in items:
                if item.get('type') == 'app':
                    results.append(SteamApp(
                        appid=item['id'],
                        name=item['name']
                    ))
                if len(results) >= limit:
                    break

            return results
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
        return []


def resolve_game_input(game_input: str) -> Tuple[Optional[str], Optional[str], List[SteamApp]]:
    """
    Resolve game input to an AppID.

    Args:
        game_input: Either a numeric AppID or a game name.

    Returns:
        Tuple of (appid, game_name, matches):
        - If input is numeric: (appid, None, [])
        - If single match found: (appid, name, [])
        - If multiple matches: (None, None, matches)
        - If no matches: (None, None, [])
    """
    # Check if input is a numeric AppID
    if game_input.isdigit():
        return (game_input, None, [])

    # Search by name
    matches = search_steam_games(game_input)

    if len(matches) == 1:
        return (str(matches[0].appid), matches[0].name, [])
    elif len(matches) > 1:
        # Check for exact match first
        query_lower = game_input.lower().strip()
        for app in matches:
            if app.name.lower() == query_lower:
                return (str(app.appid), app.name, [])
        return (None, None, matches)
    else:
        return (None, None, [])


# -----------------------------------------------------------------------------
# Feature 1: Game Launch Profiles
# -----------------------------------------------------------------------------

def get_profiles_path() -> str:
    """Get path to launch profiles config file."""
    config_dir = os.path.expanduser('~/.config/steam-proton-helper')
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, 'launch_profiles.json')


def load_launch_profiles() -> Dict[str, GameLaunchProfile]:
    """Load all launch profiles from config file."""
    profiles_path = get_profiles_path()
    profiles: Dict[str, GameLaunchProfile] = {}

    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, 'r') as f:
                data = json.load(f)
                for app_id, profile_data in data.items():
                    profiles[app_id] = GameLaunchProfile.from_dict(profile_data)
        except (json.JSONDecodeError, KeyError, IOError) as e:
            verbose_log.log(f"Error loading profiles: {e}")

    return profiles


def save_launch_profiles(profiles: Dict[str, GameLaunchProfile]) -> bool:
    """Save launch profiles to config file."""
    profiles_path = get_profiles_path()

    try:
        with open(profiles_path, 'w') as f:
            data = {app_id: profile.to_dict() for app_id, profile in profiles.items()}
            json.dump(data, f, indent=2)
        return True
    except IOError as e:
        verbose_log.log(f"Error saving profiles: {e}")
        return False


def get_launch_profile(app_id: str) -> Optional[GameLaunchProfile]:
    """Get launch profile for a specific game."""
    profiles = load_launch_profiles()
    return profiles.get(app_id)


def set_launch_profile(profile: GameLaunchProfile) -> bool:
    """Set or update a launch profile."""
    profiles = load_launch_profiles()
    profiles[profile.app_id] = profile
    return save_launch_profiles(profiles)


def delete_launch_profile(app_id: str) -> bool:
    """Delete a launch profile."""
    profiles = load_launch_profiles()
    if app_id in profiles:
        del profiles[app_id]
        return save_launch_profiles(profiles)
    return False


def generate_launch_command(profile: GameLaunchProfile) -> str:
    """Generate Steam launch command with profile settings."""
    parts = []

    # Add gamemode wrapper if enabled
    if profile.gamemode:
        parts.append("gamemoderun")

    # Add mangohud wrapper if enabled
    if profile.mangohud:
        parts.append("mangohud")

    # Add environment variables
    if profile.env_vars:
        for key, value in profile.env_vars.items():
            parts.append(f"{key}={value}")

    # Add custom launch options
    if profile.launch_options:
        parts.append(profile.launch_options)

    # Add the %command% placeholder
    parts.append("%command%")

    return " ".join(parts)


# -----------------------------------------------------------------------------
# Feature 2: Shader Cache Management
# -----------------------------------------------------------------------------

def get_shader_cache_paths(steam_root: Optional[str]) -> List[str]:
    """Get all possible shader cache directories."""
    paths = []

    if steam_root:
        # Main Steam shader cache locations
        paths.append(os.path.join(steam_root, 'steamapps', 'shadercache'))

        # DXVK state cache in compatdata
        paths.append(os.path.join(steam_root, 'steamapps', 'compatdata'))

    # Mesa shader cache
    mesa_cache = os.path.expanduser('~/.cache/mesa_shader_cache')
    if os.path.isdir(mesa_cache):
        paths.append(mesa_cache)

    # NVIDIA shader cache
    nvidia_cache = os.path.expanduser('~/.nv/GLCache')
    if os.path.isdir(nvidia_cache):
        paths.append(nvidia_cache)

    # AMD shader cache
    amd_cache = os.path.expanduser('~/.cache/AMD/GLCache')
    if os.path.isdir(amd_cache):
        paths.append(amd_cache)

    return paths


def get_directory_size(path: str) -> Tuple[int, int]:
    """Get total size and file count of a directory."""
    total_size = 0
    file_count = 0

    try:
        for dirpath, _dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                    file_count += 1
                except (OSError, IOError):
                    pass
    except (OSError, IOError):
        pass

    return total_size, file_count


def scan_shader_caches(steam_root: Optional[str]) -> List[ShaderCacheInfo]:
    """Scan for all shader caches."""
    caches: List[ShaderCacheInfo] = []

    if not steam_root:
        return caches

    shader_cache_dir = os.path.join(steam_root, 'steamapps', 'shadercache')
    if not os.path.isdir(shader_cache_dir):
        return caches

    # Each subdirectory in shadercache is an app ID
    try:
        for entry in os.listdir(shader_cache_dir):
            entry_path = os.path.join(shader_cache_dir, entry)
            if os.path.isdir(entry_path) and entry.isdigit():
                size, file_count = get_directory_size(entry_path)

                # Get last modified time
                try:
                    mtime = os.path.getmtime(entry_path)
                    from datetime import datetime
                    last_modified = datetime.fromtimestamp(mtime).isoformat()
                except OSError:
                    last_modified = None

                caches.append(ShaderCacheInfo(
                    app_id=entry,
                    name=f"App {entry}",  # Will be resolved later if possible
                    cache_path=entry_path,
                    size_bytes=size,
                    file_count=file_count,
                    last_modified=last_modified,
                ))
    except (OSError, IOError) as e:
        verbose_log.log(f"Error scanning shader caches: {e}")

    return sorted(caches, key=lambda c: c.size_bytes, reverse=True)


def clear_shader_cache(app_id: str, steam_root: Optional[str]) -> Tuple[bool, str]:
    """Clear shader cache for a specific game."""
    if not steam_root:
        return False, "Steam root not found"

    shader_cache_dir = os.path.join(steam_root, 'steamapps', 'shadercache', app_id)

    if not os.path.isdir(shader_cache_dir):
        return False, f"No shader cache found for app {app_id}"

    try:
        size_before, _ = get_directory_size(shader_cache_dir)
        shutil.rmtree(shader_cache_dir)
        return True, f"Cleared {size_before / 1024 / 1024:.1f} MB of shader cache"
    except (OSError, IOError) as e:
        return False, f"Failed to clear shader cache: {e}"


def clear_all_shader_caches(steam_root: Optional[str]) -> Tuple[bool, str]:
    """Clear all shader caches."""
    if not steam_root:
        return False, "Steam root not found"

    shader_cache_dir = os.path.join(steam_root, 'steamapps', 'shadercache')

    if not os.path.isdir(shader_cache_dir):
        return False, "No shader cache directory found"

    try:
        size_before, _ = get_directory_size(shader_cache_dir)
        shutil.rmtree(shader_cache_dir)
        os.makedirs(shader_cache_dir, exist_ok=True)
        return True, f"Cleared {size_before / 1024 / 1024:.1f} MB of shader cache"
    except (OSError, IOError) as e:
        return False, f"Failed to clear shader caches: {e}"


# -----------------------------------------------------------------------------
# Feature 3: Compatdata (Wine Prefix) Backup/Restore
# -----------------------------------------------------------------------------

def scan_compatdata(steam_root: Optional[str]) -> List[CompatdataInfo]:
    """Scan for all Wine prefixes (compatdata)."""
    prefixes: List[CompatdataInfo] = []

    if not steam_root:
        return prefixes

    libraries = get_library_paths(steam_root)

    for library in libraries:
        compatdata_dir = os.path.join(library, 'steamapps', 'compatdata')
        if not os.path.isdir(compatdata_dir):
            continue

        try:
            for entry in os.listdir(compatdata_dir):
                entry_path = os.path.join(compatdata_dir, entry)
                if os.path.isdir(entry_path) and entry.isdigit():
                    size, _ = get_directory_size(entry_path)

                    # Get last modified time
                    try:
                        mtime = os.path.getmtime(entry_path)
                        from datetime import datetime
                        last_modified = datetime.fromtimestamp(mtime).isoformat()
                    except OSError:
                        last_modified = None

                    # Try to detect Proton version from config
                    proton_version = None
                    config_path = os.path.join(entry_path, 'config_info')
                    if os.path.exists(config_path):
                        try:
                            with open(config_path, 'r') as f:
                                content = f.read()
                                # Look for Proton path in config
                                if 'Proton' in content or 'proton' in content:
                                    for line in content.split('\n'):
                                        if 'Proton' in line or 'proton' in line:
                                            proton_version = line.strip()
                                            break
                        except IOError:
                            pass

                    prefixes.append(CompatdataInfo(
                        app_id=entry,
                        name=f"App {entry}",
                        path=entry_path,
                        size_bytes=size,
                        last_modified=last_modified,
                        proton_version=proton_version,
                    ))
        except (OSError, IOError) as e:
            verbose_log.log(f"Error scanning compatdata in {library}: {e}")

    return sorted(prefixes, key=lambda p: p.size_bytes, reverse=True)


def backup_compatdata(app_id: str, steam_root: Optional[str], backup_path: Optional[str] = None) -> Tuple[bool, str]:
    """Backup a game's Wine prefix."""
    import tarfile
    from datetime import datetime

    if not steam_root:
        return False, "Steam root not found"

    # Find compatdata directory
    libraries = get_library_paths(steam_root)
    source_path = None

    for library in libraries:
        candidate = os.path.join(library, 'steamapps', 'compatdata', app_id)
        if os.path.isdir(candidate):
            source_path = candidate
            break

    if not source_path:
        return False, f"No compatdata found for app {app_id}"

    # Generate backup filename
    if backup_path is None:
        backup_dir = os.path.expanduser('~/.local/share/steam-proton-helper/backups')
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(backup_dir, f"compatdata_{app_id}_{timestamp}.tar.gz")

    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            tar.add(source_path, arcname=app_id)
        size = os.path.getsize(backup_path)
        return True, f"Backup created: {backup_path} ({size / 1024 / 1024:.1f} MB)"
    except (OSError, IOError, tarfile.TarError) as e:
        return False, f"Backup failed: {e}"


def restore_compatdata(backup_path: str, steam_root: Optional[str], app_id: Optional[str] = None) -> Tuple[bool, str]:
    """Restore a game's Wine prefix from backup."""
    import tarfile

    if not steam_root:
        return False, "Steam root not found"

    if not os.path.exists(backup_path):
        return False, f"Backup file not found: {backup_path}"

    try:
        # Extract to main Steam library
        compatdata_dir = os.path.join(steam_root, 'steamapps', 'compatdata')
        os.makedirs(compatdata_dir, exist_ok=True)

        with tarfile.open(backup_path, 'r:gz') as tar:
            # Get the app ID from the archive if not specified
            if app_id is None:
                members = tar.getnames()
                if members:
                    app_id = members[0].split('/')[0]

            if app_id:
                # Remove existing if present
                existing = os.path.join(compatdata_dir, app_id)
                if os.path.exists(existing):
                    shutil.rmtree(existing)

            tar.extractall(compatdata_dir)

        return True, f"Restored compatdata for app {app_id}"
    except (OSError, IOError, tarfile.TarError) as e:
        return False, f"Restore failed: {e}"


def list_compatdata_backups() -> List[Dict[str, Any]]:
    """List available compatdata backups."""
    backup_dir = os.path.expanduser('~/.local/share/steam-proton-helper/backups')
    backups = []

    if not os.path.isdir(backup_dir):
        return backups

    try:
        for entry in os.listdir(backup_dir):
            if entry.startswith('compatdata_') and entry.endswith('.tar.gz'):
                entry_path = os.path.join(backup_dir, entry)
                # Parse filename: compatdata_APPID_TIMESTAMP.tar.gz
                parts = entry.replace('.tar.gz', '').split('_')
                if len(parts) >= 3:
                    app_id = parts[1]
                    timestamp = '_'.join(parts[2:])

                    try:
                        size = os.path.getsize(entry_path)
                        mtime = os.path.getmtime(entry_path)
                        from datetime import datetime
                        created = datetime.fromtimestamp(mtime).isoformat()
                    except OSError:
                        size = 0
                        created = None

                    backups.append({
                        'filename': entry,
                        'path': entry_path,
                        'app_id': app_id,
                        'timestamp': timestamp,
                        'size_bytes': size,
                        'created': created,
                    })
    except OSError:
        pass

    return sorted(backups, key=lambda b: b.get('created', ''), reverse=True)


# -----------------------------------------------------------------------------
# Feature 4: Steam Library Scanner
# -----------------------------------------------------------------------------

def parse_acf_file(acf_path: str) -> Optional[Dict[str, Any]]:
    """Parse a Steam .acf manifest file."""
    try:
        with open(acf_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        data: Dict[str, Any] = {}

        # Extract key fields using regex
        patterns = {
            'appid': r'"appid"\s+"(\d+)"',
            'name': r'"name"\s+"([^"]+)"',
            'installdir': r'"installdir"\s+"([^"]+)"',
            'SizeOnDisk': r'"SizeOnDisk"\s+"(\d+)"',
            'LastPlayed': r'"LastPlayed"\s+"(\d+)"',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                data[key] = match.group(1)

        return data if data.get('appid') else None

    except (IOError, OSError) as e:
        verbose_log.log(f"Error parsing ACF file {acf_path}: {e}")
        return None


def scan_installed_games(steam_root: Optional[str]) -> List[InstalledGame]:
    """Scan for all installed Steam games."""
    games: List[InstalledGame] = []

    if not steam_root:
        return games

    libraries = get_library_paths(steam_root)

    for library in libraries:
        steamapps = os.path.join(library, 'steamapps')
        if not os.path.isdir(steamapps):
            continue

        try:
            for entry in os.listdir(steamapps):
                if entry.startswith('appmanifest_') and entry.endswith('.acf'):
                    acf_path = os.path.join(steamapps, entry)
                    data = parse_acf_file(acf_path)

                    if data and data.get('appid'):
                        app_id = data['appid']
                        name = data.get('name', f'App {app_id}')
                        install_dir = data.get('installdir', '')
                        size = int(data.get('SizeOnDisk', 0))

                        # Get Proton version from compatdata
                        proton_version = None
                        compatdata_path = os.path.join(steamapps, 'compatdata', app_id)
                        if os.path.isdir(compatdata_path):
                            config_path = os.path.join(compatdata_path, 'config_info')
                            if os.path.exists(config_path):
                                try:
                                    with open(config_path, 'r') as f:
                                        lines = f.readlines()
                                        if lines:
                                            proton_version = lines[0].strip()
                                except IOError:
                                    pass

                        # Get last played time
                        last_played = None
                        if data.get('LastPlayed'):
                            try:
                                timestamp = int(data['LastPlayed'])
                                if timestamp > 0:
                                    from datetime import datetime
                                    last_played = datetime.fromtimestamp(timestamp).isoformat()
                            except (ValueError, OSError):
                                pass

                        games.append(InstalledGame(
                            app_id=app_id,
                            name=name,
                            install_dir=os.path.join(steamapps, 'common', install_dir),
                            size_bytes=size,
                            proton_version=proton_version,
                            last_played=last_played,
                        ))
        except (OSError, IOError) as e:
            verbose_log.log(f"Error scanning library {library}: {e}")

    return sorted(games, key=lambda g: g.name.lower())


# -----------------------------------------------------------------------------
# Feature 5: Performance Tools Check
# -----------------------------------------------------------------------------

def check_performance_tools() -> List[PerformanceToolStatus]:
    """Check status of performance tools (GameMode, MangoHud, etc.)."""
    tools: List[PerformanceToolStatus] = []

    # Check GameMode
    gamemode_installed = shutil.which('gamemoderun') is not None
    gamemode_active = False
    gamemode_version = None

    if gamemode_installed:
        try:
            result = subprocess.run(['gamemoded', '--status'], capture_output=True, text=True, timeout=5)
            gamemode_active = 'active' in result.stdout.lower() or result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        try:
            result = subprocess.run(['gamemoderun', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                gamemode_version = result.stdout.strip().split('\n')[0]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    tools.append(PerformanceToolStatus(
        name="GameMode",
        installed=gamemode_installed,
        active=gamemode_active,
        version=gamemode_version,
        details="CPU governor optimization for gaming" if gamemode_installed else "Not installed - sudo apt install gamemode",
    ))

    # Check MangoHud
    mangohud_installed = shutil.which('mangohud') is not None
    mangohud_version = None

    if mangohud_installed:
        try:
            result = subprocess.run(['mangohud', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                mangohud_version = result.stdout.strip().split('\n')[0]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    tools.append(PerformanceToolStatus(
        name="MangoHud",
        installed=mangohud_installed,
        active=False,  # MangoHud is per-game, not a daemon
        version=mangohud_version,
        details="FPS/performance overlay" if mangohud_installed else "Not installed - sudo apt install mangohud",
    ))

    # Check vkBasalt
    vkbasalt_installed = os.path.exists('/usr/lib/x86_64-linux-gnu/libvkbasalt.so') or \
                         os.path.exists('/usr/lib64/libvkbasalt.so') or \
                         shutil.which('vkbasalt') is not None

    tools.append(PerformanceToolStatus(
        name="vkBasalt",
        installed=vkbasalt_installed,
        active=False,
        version=None,
        details="Vulkan post-processing layer" if vkbasalt_installed else "Not installed",
    ))

    # Check libstrangle (FPS limiter)
    strangle_installed = shutil.which('strangle') is not None or \
                        os.path.exists('/usr/lib/libstrangle.so') or \
                        os.path.exists('/usr/lib64/libstrangle.so')

    tools.append(PerformanceToolStatus(
        name="libstrangle",
        installed=strangle_installed,
        active=False,
        version=None,
        details="FPS limiter" if strangle_installed else "Not installed",
    ))

    # Check CoreCtrl (AMD GPU control)
    corectrl_installed = shutil.which('corectrl') is not None

    tools.append(PerformanceToolStatus(
        name="CoreCtrl",
        installed=corectrl_installed,
        active=False,
        version=None,
        details="AMD GPU control panel" if corectrl_installed else "Not installed (AMD only)",
    ))

    # Check GOverlay (MangoHud configurator)
    goverlay_installed = shutil.which('goverlay') is not None

    tools.append(PerformanceToolStatus(
        name="GOverlay",
        installed=goverlay_installed,
        active=False,
        version=None,
        details="MangoHud/vkBasalt GUI configurator" if goverlay_installed else "Not installed",
    ))

    return tools


# -----------------------------------------------------------------------------
# Feature 6: Log Viewer
# -----------------------------------------------------------------------------

def get_log_paths(steam_root: Optional[str]) -> List[Tuple[str, str]]:
    """Get paths to Steam/Proton log files."""
    logs: List[Tuple[str, str]] = []  # (path, type)

    # Steam logs
    if steam_root:
        steam_logs = [
            (os.path.join(steam_root, 'logs', 'bootstrap_log.txt'), 'steam'),
            (os.path.join(steam_root, 'logs', 'content_log.txt'), 'steam'),
            (os.path.join(steam_root, 'logs', 'shader_log.txt'), 'steam'),
            (os.path.join(steam_root, 'logs', 'steamwebhelper.txt'), 'steam'),
        ]
        for path, log_type in steam_logs:
            if os.path.exists(path):
                logs.append((path, log_type))

    # XDG runtime dir for Steam IPC
    runtime_dir = os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    steam_pipe = os.path.join(runtime_dir, 'steam.pipe')
    if os.path.exists(steam_pipe):
        logs.append((steam_pipe, 'steam'))

    # Proton logs in /tmp
    tmp_dir = '/tmp'
    try:
        for entry in os.listdir(tmp_dir):
            if entry.startswith('proton_') or entry.startswith('wine_'):
                path = os.path.join(tmp_dir, entry)
                if os.path.isfile(path):
                    logs.append((path, 'proton'))
    except OSError:
        pass

    # DXVK logs
    dxvk_log = os.path.expanduser('~/dxvk.log')
    if os.path.exists(dxvk_log):
        logs.append((dxvk_log, 'dxvk'))

    return logs


def parse_log_file(log_path: str, log_type: str, max_lines: int = 1000) -> List[LogEntry]:
    """Parse a log file and extract entries."""
    entries: List[LogEntry] = []

    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()[-max_lines:]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Determine log level
            level = 'INFO'
            line_lower = line.lower()
            if 'error' in line_lower or 'fail' in line_lower or 'fatal' in line_lower:
                level = 'ERROR'
            elif 'warn' in line_lower:
                level = 'WARNING'

            # Try to extract timestamp (various formats)
            timestamp = None
            # Format: [2024-01-15 10:30:45]
            ts_match = re.search(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]', line)
            if ts_match:
                timestamp = ts_match.group(1)

            entries.append(LogEntry(
                timestamp=timestamp,
                level=level,
                source=log_type,
                message=line,
                game_id=None,
            ))

    except (IOError, OSError) as e:
        verbose_log.log(f"Error reading log {log_path}: {e}")

    return entries


def scan_logs(steam_root: Optional[str], errors_only: bool = False, max_entries: int = 100) -> List[LogEntry]:
    """Scan all logs and return entries."""
    all_entries: List[LogEntry] = []

    log_paths = get_log_paths(steam_root)

    for path, log_type in log_paths:
        entries = parse_log_file(path, log_type)
        all_entries.extend(entries)

    # Filter to errors only if requested
    if errors_only:
        all_entries = [e for e in all_entries if e.level == 'ERROR']

    # Sort by timestamp (entries without timestamp go to end)
    all_entries.sort(key=lambda e: e.timestamp or 'Z', reverse=True)

    return all_entries[:max_entries]


def fetch_protondb_info(app_id: str) -> Optional[ProtonDBInfo]:
    """
    Fetch game compatibility info from ProtonDB.

    Args:
        app_id: Steam application ID.

    Returns:
        ProtonDBInfo if successful, None on error.
    """
    import urllib.request
    import urllib.error

    url = f"https://www.protondb.com/api/v1/reports/summaries/{app_id}.json"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

            return ProtonDBInfo(
                app_id=app_id,
                tier=data.get('tier', 'unknown'),
                confidence=data.get('confidence', 'unknown'),
                score=float(data.get('score', 0)),
                total_reports=int(data.get('total', 0)),
                trending_tier=data.get('trendingTier'),
                best_reported_tier=data.get('bestReportedTier'),
            )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # Game not found in ProtonDB
        raise
    except (urllib.error.URLError, json.JSONDecodeError, ValueError):
        return None


def get_tier_color(tier: str) -> str:
    """Get color for ProtonDB tier."""
    tier_colors = {
        'platinum': Color.CYAN,
        'gold': Color.YELLOW,
        'silver': Color.DIM,
        'bronze': Color.YELLOW,
        'borked': Color.RED,
        'pending': Color.BLUE,
    }
    return tier_colors.get(tier.lower(), '')


def get_tier_symbol(tier: str) -> str:
    """Get symbol for ProtonDB tier."""
    tier_symbols = {
        'platinum': '🏆',
        'gold': '🥇',
        'silver': '🥈',
        'bronze': '🥉',
        'borked': '💔',
        'pending': '⏳',
    }
    return tier_symbols.get(tier.lower(), '❓')


@dataclass
class ProtonRecommendation:
    """Proton version recommendation."""
    proton_version: str
    reason: str
    priority: int  # Lower is better


def get_proton_recommendations(info: ProtonDBInfo, installed_protons: List[str]) -> List[ProtonRecommendation]:
    """
    Generate Proton recommendations based on ProtonDB tier and installed versions.

    Args:
        info: ProtonDB game compatibility info.
        installed_protons: List of installed Proton version names.

    Returns:
        List of ProtonRecommendation objects (best first).
    """
    recommendations = []
    tier = info.tier.lower()

    # Normalize installed names for comparison
    installed_lower = [p.lower() for p in installed_protons]

    # Check for GE-Proton in installed versions
    has_ge = any('ge-proton' in p or 'proton-ge' in p for p in installed_lower)
    _ = has_ge  # Used in recommendation logic below

    if tier == 'platinum':
        # Platinum: Works great, recommend latest stable Proton
        recommendations.append(ProtonRecommendation(
            proton_version="Proton Experimental",
            reason="Platinum rating - works out of the box with latest Proton",
            priority=1
        ))
        if has_ge:
            recommendations.append(ProtonRecommendation(
                proton_version="GE-Proton (latest)",
                reason="GE-Proton also excellent for platinum games",
                priority=2
            ))
    elif tier == 'gold':
        # Gold: Works with tweaks, GE-Proton often helps
        recommendations.append(ProtonRecommendation(
            proton_version="GE-Proton (latest)",
            reason="Gold rating - GE-Proton often has fixes for minor issues",
            priority=1
        ))
        recommendations.append(ProtonRecommendation(
            proton_version="Proton Experimental",
            reason="Latest experimental also works well",
            priority=2
        ))
    elif tier == 'silver':
        # Silver: Has issues, GE-Proton strongly recommended
        recommendations.append(ProtonRecommendation(
            proton_version="GE-Proton (latest)",
            reason="Silver rating - GE-Proton includes extra patches and codecs",
            priority=1
        ))
        recommendations.append(ProtonRecommendation(
            proton_version="Proton Experimental",
            reason="Try experimental if GE doesn't work",
            priority=2
        ))
    elif tier == 'bronze':
        # Bronze: Problematic, try GE-Proton or older versions
        recommendations.append(ProtonRecommendation(
            proton_version="GE-Proton (latest)",
            reason="Bronze rating - GE-Proton may have specific game fixes",
            priority=1
        ))
        recommendations.append(ProtonRecommendation(
            proton_version="Proton 8.0 or older",
            reason="Older Proton versions sometimes work better for problematic games",
            priority=2
        ))
    elif tier == 'borked':
        # Borked: Very problematic
        recommendations.append(ProtonRecommendation(
            proton_version="GE-Proton (latest)",
            reason="Borked rating - GE-Proton is the best chance for problematic games",
            priority=1
        ))
        recommendations.append(ProtonRecommendation(
            proton_version="Check ProtonDB reports",
            reason="Game may require specific tweaks or launch options",
            priority=2
        ))
    else:
        # Pending or unknown
        recommendations.append(ProtonRecommendation(
            proton_version="Proton Experimental",
            reason="Not enough data - try latest experimental first",
            priority=1
        ))
        recommendations.append(ProtonRecommendation(
            proton_version="GE-Proton (latest)",
            reason="GE-Proton if experimental doesn't work",
            priority=2
        ))

    return sorted(recommendations, key=lambda r: r.priority)


# -----------------------------------------------------------------------------
# GE-Proton Installation
# -----------------------------------------------------------------------------

@dataclass
class GEProtonRelease:
    """Information about a GE-Proton release."""
    tag_name: str
    name: str
    download_url: str
    size_bytes: int
    published_at: str


def fetch_ge_proton_releases(limit: int = 10) -> List[GEProtonRelease]:
    """
    Fetch available GE-Proton releases from GitHub.

    Args:
        limit: Maximum number of releases to fetch.

    Returns:
        List of GEProtonRelease objects.
    """
    import urllib.request
    import urllib.error

    url = f"https://api.github.com/repos/GloriousEggroll/proton-ge-custom/releases?per_page={limit}"

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'steam-proton-helper'})
        with urllib.request.urlopen(req, timeout=15) as response:
            releases_data = json.loads(response.read().decode('utf-8'))

            releases = []
            for r in releases_data:
                # Find the .tar.gz asset
                tar_asset = None
                for asset in r.get('assets', []):
                    if asset['name'].endswith('.tar.gz') and 'proton' in asset['name'].lower():
                        tar_asset = asset
                        break

                if tar_asset:
                    releases.append(GEProtonRelease(
                        tag_name=r['tag_name'],
                        name=r['name'],
                        download_url=tar_asset['browser_download_url'],
                        size_bytes=tar_asset['size'],
                        published_at=r['published_at'][:10],  # Just the date
                    ))

            return releases
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        verbose_log.log(f"Error fetching GE-Proton releases: {e}")
        return []


def get_proton_install_dir(variant: Optional[SteamVariant] = None) -> Optional[str]:
    """
    Get the compatibilitytools.d directory for installing custom Proton.

    Args:
        variant: Steam installation variant.

    Returns:
        Path to compatibilitytools.d or None if not found.
    """
    # Check common locations
    paths_to_try = [
        os.path.expanduser('~/.steam/root/compatibilitytools.d'),
        os.path.expanduser('~/.local/share/Steam/compatibilitytools.d'),
        os.path.expanduser('~/.var/app/com.valvesoftware.Steam/data/Steam/compatibilitytools.d'),
    ]

    # Also check based on detected Steam root
    steam_root = find_steam_root()
    if steam_root:
        paths_to_try.insert(0, os.path.join(steam_root, 'compatibilitytools.d'))

    for path in paths_to_try:
        parent = os.path.dirname(path)
        if os.path.isdir(parent):
            # Create compatibilitytools.d if parent exists
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                    verbose_log.log(f"Created directory: {path}")
                except OSError:
                    continue
            return path

    return None


def download_with_progress(url: str, dest_path: str, show_progress: bool = True) -> bool:
    """
    Download a file with progress indication.

    Args:
        url: URL to download from.
        dest_path: Destination file path.
        show_progress: Whether to show progress bar.

    Returns:
        True if successful, False otherwise.
    """
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'steam-proton-helper'})

        with urllib.request.urlopen(req, timeout=30) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            block_size = 8192
            downloaded = 0

            with open(dest_path, 'wb') as f:
                while True:
                    chunk = response.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if show_progress and total_size > 0:
                        percent = (downloaded / total_size) * 100
                        mb_downloaded = downloaded / (1024 * 1024)
                        mb_total = total_size / (1024 * 1024)
                        print(f"\r  Downloading: {mb_downloaded:.1f}/{mb_total:.1f} MB ({percent:.1f}%)", end='', flush=True)

            if show_progress:
                print()  # New line after progress

        return True
    except (urllib.error.URLError, OSError) as e:
        verbose_log.log(f"Download error: {e}")
        return False


def install_ge_proton(version: str, force: bool = False) -> Tuple[bool, str]:
    """
    Download and install a GE-Proton version.

    Args:
        version: Version to install (e.g., "GE-Proton10-26" or "latest").
        force: Overwrite if already installed.

    Returns:
        Tuple of (success, message).
    """
    import tarfile
    import tempfile

    # Fetch releases
    releases = fetch_ge_proton_releases(limit=20)
    if not releases:
        return False, "Failed to fetch GE-Proton releases. Check your internet connection."

    # Find the requested version
    target_release = None
    if version.lower() == 'latest':
        target_release = releases[0]
    else:
        # Try exact match first
        for r in releases:
            if r.tag_name.lower() == version.lower():
                target_release = r
                break
        # Try partial match
        if not target_release:
            for r in releases:
                if version.lower() in r.tag_name.lower():
                    target_release = r
                    break

    if not target_release:
        available = ', '.join([r.tag_name for r in releases[:5]])
        return False, f"Version '{version}' not found. Available: {available}..."

    # Get install directory
    install_dir = get_proton_install_dir()
    if not install_dir:
        return False, "Could not find Steam compatibilitytools.d directory. Is Steam installed?"

    # Check if already installed
    target_path = os.path.join(install_dir, target_release.tag_name)
    if os.path.exists(target_path):
        if not force:
            return False, f"{target_release.tag_name} is already installed. Use --force to reinstall."
        else:
            shutil.rmtree(target_path)
            verbose_log.log(f"Removed existing installation: {target_path}")

    # Download
    print(f"\n{Color.BOLD}Installing {target_release.tag_name}{Color.END}")
    print(f"  Size: {target_release.size_bytes / (1024 * 1024):.0f} MB")
    print(f"  Released: {target_release.published_at}")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        tar_path = os.path.join(tmpdir, f"{target_release.tag_name}.tar.gz")

        # Download
        if not download_with_progress(target_release.download_url, tar_path):
            return False, "Download failed. Check your internet connection."

        # Extract
        print(f"  Extracting to {install_dir}...")
        try:
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(path=install_dir)
        except (tarfile.TarError, OSError) as e:
            return False, f"Extraction failed: {e}"

    # Verify installation
    if os.path.isdir(target_path):
        return True, f"Successfully installed {target_release.tag_name}\n  Location: {target_path}\n\n  Restart Steam to use it."
    else:
        return True, f"Installed to {install_dir}. Restart Steam to use it."


def get_removable_proton_versions() -> List[Tuple[str, str]]:
    """
    Get list of custom Proton versions that can be removed.

    Only returns Proton installations in compatibilitytools.d (custom builds).
    Does NOT include official Steam Proton versions.

    Returns:
        List of tuples (name, path) for removable Proton versions.
    """
    steam_root = find_steam_root()
    if not steam_root:
        return []

    protons = find_proton_installations(steam_root)
    removable = []

    for p in protons:
        # Only include custom Proton from compatibilitytools.d
        if 'compatibilitytools.d' in p.path:
            removable.append((p.name, p.path))

    return removable


def remove_ge_proton(version: str, confirm: bool = True) -> Tuple[bool, str]:
    """
    Remove a custom Proton version.

    Args:
        version: Version name to remove (e.g., "GE-Proton10-26").
        confirm: Whether to prompt for confirmation (skipped if --yes).

    Returns:
        Tuple of (success, message).
    """
    # Get removable versions
    removable = get_removable_proton_versions()

    if not removable:
        return False, "No custom Proton versions found to remove."

    # Find the requested version
    target = None
    for name, path in removable:
        if name.lower() == version.lower():
            target = (name, path)
            break

    # Try partial match
    if not target:
        for name, path in removable:
            if version.lower() in name.lower():
                target = (name, path)
                break

    if not target:
        available = ', '.join([name for name, _ in removable[:5]])
        return False, f"Version '{version}' not found. Available: {available}"

    name, path = target

    # Safety check - ensure it's in compatibilitytools.d
    if 'compatibilitytools.d' not in path:
        return False, f"Cannot remove {name}: not a custom Proton version (official Steam Proton)."

    # Confirm removal
    if confirm:
        print(f"\n{Color.YELLOW}Warning:{Color.END} This will permanently delete:")
        print(f"  {path}")
        try:
            response = input(f"\nRemove {name}? [y/N] ").strip().lower()
            if response not in ('y', 'yes'):
                return False, "Removal cancelled."
        except (KeyboardInterrupt, EOFError):
            return False, "Removal cancelled."

    # Remove the directory
    try:
        shutil.rmtree(path)
        return True, f"Successfully removed {name}"
    except PermissionError:
        return False, f"Permission denied removing {path}. Try running with sudo."
    except OSError as e:
        return False, f"Failed to remove {name}: {e}"


def check_ge_proton_updates() -> List[Dict[str, Any]]:
    """
    Check for available GE-Proton updates.

    Returns:
        List of dicts with 'installed', 'latest', 'update_available' keys.
    """
    # Get installed custom Proton versions
    steam_root = find_steam_root()
    if not steam_root:
        return []

    protons = find_proton_installations(steam_root)
    installed_ge = [p for p in protons if 'compatibilitytools.d' in p.path and 'GE-Proton' in p.name]

    # Fetch latest release
    releases = fetch_ge_proton_releases(limit=1)
    if not releases:
        return []

    latest = releases[0]

    results = []
    for p in installed_ge:
        # Extract version number for comparison
        installed_ver = p.name
        is_latest = installed_ver.lower() == latest.tag_name.lower()

        results.append({
            'installed': installed_ver,
            'path': p.path,
            'latest': latest.tag_name,
            'update_available': not is_latest,
        })

    # If no GE-Proton installed, indicate latest available
    if not installed_ge:
        results.append({
            'installed': None,
            'path': None,
            'latest': latest.tag_name,
            'update_available': True,
        })

    return results


def update_ge_proton(force: bool = False) -> Tuple[bool, str]:
    """
    Update to the latest GE-Proton version.

    Args:
        force: Force reinstall even if already at latest.

    Returns:
        Tuple of (success, message).
    """
    # Check what's installed
    updates = check_ge_proton_updates()

    if not updates:
        return False, "Could not check for updates. Check your internet connection."

    # Find the latest version
    latest_version = updates[0]['latest'] if updates else None
    if not latest_version:
        return False, "Could not determine latest GE-Proton version."

    # Check if already have latest
    has_latest = any(u['installed'] and u['installed'].lower() == latest_version.lower() for u in updates)

    if has_latest and not force:
        return True, f"Already up to date: {latest_version}"

    # Install the latest version
    success, message = install_ge_proton(latest_version, force=force)
    return success, message


def print_protondb_info(info: ProtonDBInfo, use_color: bool = True) -> None:
    """Print ProtonDB compatibility info."""
    tier_color = get_tier_color(info.tier) if use_color else ''
    reset = Color.END if use_color else ''
    bold = Color.BOLD if use_color else ''

    symbol = get_tier_symbol(info.tier)
    tier_display = info.tier.upper()

    print(f"\n{bold}ProtonDB Compatibility for AppID {info.app_id}{reset}")
    print("─" * 44)
    print(f"  {symbol} Rating: {tier_color}{tier_display}{reset}")
    print(f"  📊 Score: {info.score:.2f}")
    print(f"  📝 Reports: {info.total_reports}")
    print(f"  🎯 Confidence: {info.confidence}")

    if info.best_reported_tier and info.best_reported_tier != info.tier:
        best_color = get_tier_color(info.best_reported_tier) if use_color else ''
        print(f"  ⭐ Best Reported: {best_color}{info.best_reported_tier.upper()}{reset}")

    if info.trending_tier and info.trending_tier != info.tier:
        trend_color = get_tier_color(info.trending_tier) if use_color else ''
        print(f"  📈 Trending: {trend_color}{info.trending_tier.upper()}{reset}")

    print()

    # Print tier explanation
    tier_info = {
        'platinum': 'Runs perfectly out of the box',
        'gold': 'Runs perfectly after tweaks',
        'silver': 'Runs with minor issues',
        'bronze': 'Runs, but often crashes or has issues',
        'borked': 'Game does not run or is unplayable',
        'pending': 'Not enough reports yet',
    }
    if info.tier.lower() in tier_info:
        print(f"  ℹ️  {tier_info[info.tier.lower()]}")

    print(f"\n  🔗 https://www.protondb.com/app/{info.app_id}")


def output_protondb_json(info: Optional[ProtonDBInfo], app_id: str) -> None:
    """Output ProtonDB info as JSON."""
    if info:
        data = {
            'app_id': info.app_id,
            'tier': info.tier,
            'score': info.score,
            'confidence': info.confidence,
            'total_reports': info.total_reports,
            'best_reported_tier': info.best_reported_tier,
            'trending_tier': info.trending_tier,
            'url': f'https://www.protondb.com/app/{info.app_id}',
        }
    else:
        data = {
            'app_id': app_id,
            'error': 'Game not found in ProtonDB',
        }
    print(json.dumps(data, indent=2))


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
    print("  • Enable Proton in Steam: Settings → Compatibility → Enable Steam Play")
    print("  • Keep graphics drivers updated for best performance")
    print("  • Check game compatibility at protondb.com")
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
            response = input("Continue? [y/N] ").strip().lower()
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
  %(prog)s                       Run all checks with colored output
  %(prog)s --json                Output results as JSON
  %(prog)s --list-proton         List all detected Proton versions
  %(prog)s --install-proton list List available GE-Proton versions
  %(prog)s --install-proton latest  Install latest GE-Proton
  %(prog)s --remove-proton list  List removable custom Proton versions
  %(prog)s --remove-proton GE-Proton9-7  Remove a custom Proton version
  %(prog)s --check-updates       Check if newer GE-Proton is available
  %(prog)s --update-proton       Update to latest GE-Proton
  %(prog)s --game "elden ring"   Check ProtonDB rating by game name
  %(prog)s --game 292030         Check ProtonDB rating by AppID
  %(prog)s --game A --game B     Check multiple games
  %(prog)s --search "witcher"    Search Steam for games
  %(prog)s --fix                 Print fix script to stdout
  %(prog)s --fix fix.sh          Write fix script to file
  %(prog)s --dry-run             Show what --apply would install
  %(prog)s --apply               Install missing packages (prompts for confirmation)
  %(prog)s --apply -y            Install without confirmation prompt
  %(prog)s --no-color            Disable colored output
  %(prog)s --verbose             Show debug information

Note: Use --dry-run to preview before --apply. Requires sudo for installation.
      Use --game with a game name or Steam AppID to check ProtonDB compatibility.
      Use --search to find AppIDs without querying ProtonDB.
      Use --list-proton to see all installed Proton versions.
      Use --install-proton to download and install GE-Proton.
      Use --remove-proton to uninstall custom Proton versions.
      Use --check-updates to see if newer GE-Proton is available.
      Use --update-proton to update to the latest GE-Proton.
"""
    )

    parser.add_argument(
        '--version', '-V',
        action='version',
        version=f'%(prog)s {__version__}'
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

    parser.add_argument(
        '--game',
        metavar='NAME',
        action='append',
        help='Check ProtonDB compatibility by game name or AppID (can be used multiple times)'
    )

    parser.add_argument(
        '--search',
        metavar='QUERY',
        help='Search Steam for games by name (returns AppIDs without ProtonDB lookup)'
    )

    parser.add_argument(
        '--list-proton',
        action='store_true',
        help='List all detected Proton installations'
    )

    parser.add_argument(
        '--install-proton',
        metavar='VERSION',
        help='Install GE-Proton version (use "latest" for newest, "list" to see available)'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force reinstall even if version already exists (use with --install-proton)'
    )

    parser.add_argument(
        '--remove-proton',
        metavar='VERSION',
        help='Remove a custom Proton version (use "list" to see removable versions)'
    )

    parser.add_argument(
        '--update-proton',
        action='store_true',
        help='Update all installed GE-Proton versions to the latest release'
    )

    parser.add_argument(
        '--check-updates',
        action='store_true',
        help='Check if newer GE-Proton versions are available (no installation)'
    )

    parser.add_argument(
        '--recommend',
        metavar='GAME',
        help='Recommend best Proton version for a game based on ProtonDB reports'
    )

    # Feature: Steam library scanner
    parser.add_argument(
        '--list-games',
        action='store_true',
        help='List installed Steam games with their Proton versions'
    )

    # Feature: Game launch profiles
    parser.add_argument(
        '--profile',
        metavar='ACTION',
        nargs='?',
        const='list',
        help='Manage launch profiles: list, get <appid>, set <appid> [options], delete <appid>'
    )

    parser.add_argument(
        '--profile-proton',
        metavar='VERSION',
        help='Proton version to use with --profile set (e.g., "GE-Proton10-26")'
    )

    parser.add_argument(
        '--profile-options',
        metavar='OPTIONS',
        help='Launch options to use with --profile set'
    )

    parser.add_argument(
        '--profile-mangohud',
        action='store_true',
        help='Enable MangoHud for profile'
    )

    parser.add_argument(
        '--profile-gamemode',
        action='store_true',
        help='Enable GameMode for profile'
    )

    # Feature: Shader cache management
    parser.add_argument(
        '--shader-cache',
        metavar='ACTION',
        nargs='?',
        const='list',
        help='Manage shader caches: list, clear <appid|all>'
    )

    # Feature: Compatdata backup/restore
    parser.add_argument(
        '--compatdata',
        metavar='ACTION',
        nargs='?',
        const='list',
        help='Manage Wine prefixes: list, backup <appid>, restore <appid>, backups'
    )

    parser.add_argument(
        '--backup-dir',
        metavar='DIR',
        help='Directory for compatdata backups (default: ~/.local/share/steam-proton-helper/backups)'
    )

    # Feature: Performance tools check
    parser.add_argument(
        '--perf-tools',
        action='store_true',
        help='Check status of gaming performance tools (GameMode, MangoHud, etc.)'
    )

    # Feature: Log viewer
    parser.add_argument(
        '--logs',
        metavar='TYPE',
        nargs='?',
        const='all',
        help='View Steam/Proton logs: all, errors, steam, proton, dxvk'
    )

    parser.add_argument(
        '--log-lines',
        metavar='N',
        type=int,
        default=50,
        help='Number of log entries to show (default: 50)'
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

    # Handle --search flag (Steam game search)
    if args.search:
        try:
            results = search_steam_games(args.search, limit=20)

            if args.json:
                output = {
                    "query": args.search,
                    "results": [{"appid": r.appid, "name": r.name} for r in results]
                }
                print(json.dumps(output, indent=2))
            elif results:
                print(f"Search results for '{args.search}':\n")
                for i, app in enumerate(results, 1):
                    print(f"  {i:2}. {app.name}")
                    print(f"      AppID: {app.appid}")
                    print(f"      https://store.steampowered.com/app/{app.appid}")
                    if i < len(results):
                        print()
                print("\nUse --game <AppID> to check ProtonDB compatibility.")
            else:
                print(f"No games found matching '{args.search}'.")
                return 1
            return 0
        except Exception as e:
            print(f"Error searching Steam: {e}", file=sys.stderr)
            return 1

    # Handle --list-proton flag
    if getattr(args, 'list_proton', False):
        # Detect Steam
        variant, steam_msg = detect_steam_variant()
        steam_root = find_steam_root()

        if not steam_root:
            if args.json:
                print(json.dumps({"error": "Steam not found", "proton_installations": []}, indent=2))
            else:
                print(f"{Color.RED}✗ Steam not found{Color.END}")
                print("  Install Steam first to detect Proton versions.")
            return 1

        # Find Proton installations
        protons = find_proton_installations(steam_root)

        if args.json:
            output = {
                "steam_root": steam_root,
                "steam_variant": variant.value if variant else None,
                "count": len(protons),
                "proton_installations": [
                    {
                        "name": p.name,
                        "path": p.path,
                        "has_executable": p.has_executable,
                        "has_toolmanifest": p.has_toolmanifest,
                        "has_version": p.has_version,
                        "type": "custom" if "compatibilitytools.d" in p.path else "official"
                    }
                    for p in sorted(protons, key=lambda x: x.name.lower())
                ]
            }
            print(json.dumps(output, indent=2))
        else:
            if protons:
                print(f"\n{Color.BOLD}Proton Installations{Color.END} ({len(protons)} found)\n")
                print(f"  Steam Root: {steam_root}\n")

                # Separate official and custom
                official = [p for p in protons if "compatibilitytools.d" not in p.path]
                custom = [p for p in protons if "compatibilitytools.d" in p.path]

                if official:
                    print(f"  {Color.CYAN}── Official (Steam) ──{Color.END}")
                    for p in sorted(official, key=lambda x: x.name.lower()):
                        status = f"{Color.GREEN}✓{Color.END}" if p.has_executable else f"{Color.YELLOW}?{Color.END}"
                        print(f"    {status} {p.name}")
                        if args.verbose:
                            print(f"      {Color.DIM}{p.path}{Color.END}")
                    print()

                if custom:
                    print(f"  {Color.CYAN}── Custom (compatibilitytools.d) ──{Color.END}")
                    for p in sorted(custom, key=lambda x: x.name.lower()):
                        status = f"{Color.GREEN}✓{Color.END}" if p.has_executable else f"{Color.YELLOW}?{Color.END}"
                        print(f"    {status} {p.name}")
                        if args.verbose:
                            print(f"      {Color.DIM}{p.path}{Color.END}")
                    print()

                print(f"  {Color.DIM}Use --verbose to see full paths{Color.END}")
            else:
                print(f"\n{Color.YELLOW}No Proton installations found.{Color.END}")
                print("\nTo install Proton:")
                print("  1. Open Steam → Settings → Compatibility")
                print("  2. Enable 'Enable Steam Play for all other titles'")
                print("  3. Select a Proton version and restart Steam")
                print("\nFor GE-Proton, see: https://github.com/GloriousEggroll/proton-ge-custom")
                print("  Or use: steam-proton-helper --install-proton latest")
        return 0

    # Handle --install-proton flag
    if args.install_proton:
        version = args.install_proton

        # Handle "list" command
        if version.lower() == 'list':
            releases = fetch_ge_proton_releases(limit=15)

            if not releases:
                if args.json:
                    print(json.dumps({"error": "Failed to fetch releases", "releases": []}, indent=2))
                else:
                    print(f"{Color.RED}Failed to fetch releases. Check your internet connection.{Color.END}")
                return 1

            if args.json:
                output = {
                    "releases": [
                        {
                            "version": r.tag_name,
                            "name": r.name,
                            "size_mb": round(r.size_bytes / (1024 * 1024)),
                            "released": r.published_at,
                            "download_url": r.download_url
                        }
                        for r in releases
                    ]
                }
                print(json.dumps(output, indent=2))
            else:
                print(f"\n{Color.BOLD}Available GE-Proton Releases{Color.END}\n")
                # Check what's installed
                steam_root = find_steam_root()
                installed_protons = find_proton_installations(steam_root) if steam_root else []
                installed_names = {p.name.lower() for p in installed_protons}

                for r in releases:
                    size_mb = r.size_bytes / (1024 * 1024)
                    is_installed = r.tag_name.lower() in installed_names

                    if is_installed:
                        status = f"{Color.GREEN}✓ installed{Color.END}"
                    else:
                        status = ""

                    print(f"  {r.tag_name:<20} {size_mb:>6.0f} MB  {r.published_at}  {status}")

                print(f"\n  {Color.DIM}Install with: steam-proton-helper --install-proton <version>{Color.END}")
                print(f"  {Color.DIM}Example: steam-proton-helper --install-proton latest{Color.END}")
            return 0

        # Install the requested version
        try:
            success, message = install_ge_proton(version, force=args.force)
            if success:
                print(f"\n{Color.GREEN}✓ {message}{Color.END}")
                return 0
            else:
                print(f"\n{Color.RED}✗ {message}{Color.END}")
                return 1
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Installation cancelled.{Color.END}")
            return 130
        except Exception as e:
            print(f"\n{Color.RED}Error: {e}{Color.END}")
            return 1

    # Handle --remove-proton flag
    if args.remove_proton:
        version = args.remove_proton

        # Handle "list" command
        if version.lower() == 'list':
            removable = get_removable_proton_versions()

            if args.json:
                output = {
                    "removable": [
                        {"name": name, "path": path}
                        for name, path in removable
                    ]
                }
                print(json.dumps(output, indent=2))
            elif removable:
                print(f"\n{Color.BOLD}Removable Custom Proton Versions{Color.END}\n")
                print(f"  {Color.DIM}Only custom Proton versions (in compatibilitytools.d) can be removed.{Color.END}")
                print(f"  {Color.DIM}Official Steam Proton versions are managed by Steam.{Color.END}\n")

                for name, path in removable:
                    print(f"  {Color.CYAN}{name}{Color.END}")
                    if args.verbose:
                        print(f"    {Color.DIM}{path}{Color.END}")

                print(f"\n  {Color.DIM}Remove with: steam-proton-helper --remove-proton <version>{Color.END}")
                print(f"  {Color.DIM}Skip confirmation: steam-proton-helper --remove-proton <version> -y{Color.END}")
            else:
                print(f"\n{Color.YELLOW}No custom Proton versions found to remove.{Color.END}")
                print("  Custom Proton versions are installed in ~/.steam/root/compatibilitytools.d/")
                print("  Use --install-proton to install GE-Proton.")
            return 0

        # Remove the requested version
        try:
            confirm = not args.yes
            success, message = remove_ge_proton(version, confirm=confirm)
            if success:
                print(f"\n{Color.GREEN}✓ {message}{Color.END}")
                print("  Restart Steam to update the Proton list.")
                return 0
            else:
                print(f"\n{Color.RED}✗ {message}{Color.END}")
                return 1
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Removal cancelled.{Color.END}")
            return 130
        except Exception as e:
            print(f"\n{Color.RED}Error: {e}{Color.END}")
            return 1

    # Handle --check-updates flag
    if args.check_updates:
        try:
            updates = check_ge_proton_updates()

            if args.json:
                print(json.dumps({"updates": updates}, indent=2))
            elif updates:
                print(f"\n{Color.BOLD}GE-Proton Update Status{Color.END}\n")

                for u in updates:
                    if u['installed']:
                        if u['update_available']:
                            print(f"  {Color.YELLOW}⬆{Color.END} {u['installed']} → {Color.GREEN}{u['latest']}{Color.END} (update available)")
                        else:
                            print(f"  {Color.GREEN}✓{Color.END} {u['installed']} (up to date)")
                    else:
                        print(f"  {Color.CYAN}ℹ{Color.END} No GE-Proton installed. Latest: {Color.GREEN}{u['latest']}{Color.END}")

                any_updates = any(u['update_available'] for u in updates)
                if any_updates:
                    print(f"\n  {Color.DIM}Run: steam-proton-helper --update-proton{Color.END}")
            else:
                print(f"{Color.RED}Could not check for updates.{Color.END}")
                return 1
            return 0
        except Exception as e:
            print(f"\n{Color.RED}Error: {e}{Color.END}")
            return 1

    # Handle --update-proton flag
    if args.update_proton:
        try:
            print(f"\n{Color.BOLD}Checking for GE-Proton updates...{Color.END}")
            success, message = update_ge_proton(force=args.force)
            if success:
                print(f"\n{Color.GREEN}✓ {message}{Color.END}")
                return 0
            else:
                print(f"\n{Color.RED}✗ {message}{Color.END}")
                return 1
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Update cancelled.{Color.END}")
            return 130
        except Exception as e:
            print(f"\n{Color.RED}Error: {e}{Color.END}")
            return 1

    # Handle --game flag (ProtonDB lookup)
    if args.game:
        # Expand comma-separated values and flatten the list
        games_to_check = []
        for game_arg in args.game:
            # Split by comma, but be careful with game names containing commas
            # Only split if the result looks like multiple entries (no spaces around commas)
            if ',' in game_arg and not any(c.isalpha() for c in game_arg.split(',')[0][-1:]):
                # Likely comma-separated AppIDs like "292030,1245620"
                games_to_check.extend([g.strip() for g in game_arg.split(',') if g.strip()])
            else:
                games_to_check.append(game_arg)

        # Process each game
        results = []
        errors = []
        use_color = not args.no_color

        for game_input in games_to_check:
            try:
                # Resolve game input (AppID or name)
                app_id, game_name, matches = resolve_game_input(game_input)

                # Handle multiple matches
                if matches:
                    errors.append({
                        "query": game_input,
                        "error": "multiple_matches",
                        "matches": [{"appid": m.appid, "name": m.name} for m in matches]
                    })
                    continue

                # Handle no matches
                if not app_id:
                    errors.append({
                        "query": game_input,
                        "error": "not_found",
                        "message": f"No games found matching '{game_input}'"
                    })
                    continue

                # Fetch ProtonDB info
                info = fetch_protondb_info(app_id)
                results.append({
                    "query": game_input,
                    "app_id": app_id,
                    "game_name": game_name,
                    "info": info
                })

            except Exception as e:
                errors.append({
                    "query": game_input,
                    "error": "fetch_error",
                    "message": str(e)
                })

        # Output results
        if args.json:
            output = {
                "games": [],
                "errors": errors
            }
            for r in results:
                if r["info"]:
                    output["games"].append({
                        "query": r["query"],
                        "app_id": r["app_id"],
                        "name": r["game_name"] or r["query"],
                        "tier": r["info"].tier,
                        "score": r["info"].score,
                        "confidence": r["info"].confidence,
                        "total_reports": r["info"].total_reports,
                        "best_reported_tier": r["info"].best_reported_tier,
                        "trending_tier": r["info"].trending_tier,
                        "url": f"https://www.protondb.com/app/{r['app_id']}"
                    })
                else:
                    output["errors"].append({
                        "query": r["query"],
                        "app_id": r["app_id"],
                        "error": "not_in_protondb"
                    })
            print(json.dumps(output, indent=2))
        else:
            # Print results for each game
            for i, r in enumerate(results):
                if i > 0:
                    print()  # Separator between games

                if r["game_name"]:
                    print(f"Found: {r['game_name']} (AppID: {r['app_id']})\n")

                if r["info"]:
                    print_protondb_info(r["info"], use_color=use_color)
                else:
                    print(f"Game with AppID {r['app_id']} not found in ProtonDB.")
                    print(f"Check https://store.steampowered.com/app/{r['app_id']}")

            # Print errors
            for err in errors:
                print()
                if err["error"] == "multiple_matches":
                    print(f"Multiple games found for '{err['query']}':")
                    for j, m in enumerate(err["matches"], 1):
                        print(f"  {j}. {m['name']} (AppID: {m['appid']})")
                    print("Use --game <AppID> for the specific game.")
                elif err["error"] == "not_found":
                    print(f"No games found matching '{err['query']}'.")
                else:
                    print(f"Error checking '{err['query']}': {err.get('message', 'Unknown error')}")

        # Return 1 if any errors, 0 if all succeeded
        return 1 if errors else 0

    # Handle --list-games flag (Steam library scanner)
    if getattr(args, 'list_games', False):
        steam_root = find_steam_root()
        if not steam_root:
            if args.json:
                print(json.dumps({"error": "Steam not found", "games": []}, indent=2))
            else:
                print(f"{Color.RED}✗ Steam not found{Color.END}")
            return 1

        games = scan_installed_games(steam_root)

        if args.json:
            output = {
                "steam_root": steam_root,
                "count": len(games),
                "games": [g.to_dict() for g in games]
            }
            print(json.dumps(output, indent=2))
        elif games:
            print(f"\n{Color.BOLD}Installed Steam Games{Color.END} ({len(games)} found)\n")

            total_size = sum(g.size_bytes for g in games)
            print(f"  Total size: {total_size / (1024**3):.1f} GB\n")

            # Sort by name
            for g in sorted(games, key=lambda x: x.name.lower()):
                size_gb = g.size_bytes / (1024**3)
                proton = g.proton_version or "Native"
                print(f"  {g.name}")
                print(f"    AppID: {g.app_id}  Size: {size_gb:.1f} GB  Proton: {proton}")
                if args.verbose and g.last_played:
                    print(f"    Last played: {g.last_played}  Playtime: {g.playtime_hours:.1f}h")
        else:
            print(f"{Color.YELLOW}No installed games found.{Color.END}")
        return 0

    # Handle --perf-tools flag (Performance tools check)
    if getattr(args, 'perf_tools', False):
        tools = check_performance_tools()

        if args.json:
            output = {
                "tools": [
                    {
                        "name": t.name,
                        "installed": t.installed,
                        "active": t.active,
                        "version": t.version,
                        "details": t.details,
                    }
                    for t in tools
                ]
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"\n{Color.BOLD}Gaming Performance Tools{Color.END}\n")

            for t in tools:
                if t.installed:
                    status = f"{Color.GREEN}✓{Color.END}"
                    active_str = f" {Color.CYAN}(active){Color.END}" if t.active else ""
                    version_str = f" v{t.version}" if t.version else ""
                    print(f"  {status} {Color.BOLD}{t.name}{Color.END}{version_str}{active_str}")
                else:
                    print(f"  {Color.DIM}○{Color.END} {t.name} - {t.details}")

            print(f"\n{Color.DIM}Install performance tools with your package manager.{Color.END}")
        return 0

    # Handle --logs flag (Log viewer)
    if getattr(args, 'logs', None) is not None:
        steam_root = find_steam_root()
        log_filter = args.logs.lower() if args.logs else 'all'
        max_entries = args.log_lines

        errors_only = (log_filter == 'errors')
        entries = scan_logs(steam_root, errors_only=errors_only, max_entries=max_entries)

        # Filter by source if requested
        if log_filter not in ('all', 'errors'):
            entries = [e for e in entries if e.source == log_filter]

        if args.json:
            output = {
                "filter": log_filter,
                "count": len(entries),
                "entries": [
                    {
                        "timestamp": e.timestamp,
                        "level": e.level,
                        "source": e.source,
                        "message": e.message,
                    }
                    for e in entries
                ]
            }
            print(json.dumps(output, indent=2))
        elif entries:
            print(f"\n{Color.BOLD}Steam/Proton Logs{Color.END} ({len(entries)} entries)\n")

            for e in entries:
                level_color = {
                    'ERROR': Color.RED,
                    'WARNING': Color.YELLOW,
                    'INFO': Color.DIM,
                }.get(e.level, '')

                ts = e.timestamp or ''
                source = f"[{e.source}]"
                print(f"  {ts} {level_color}{e.level:7}{Color.END} {source:10} {e.message[:80]}")
        else:
            print(f"{Color.YELLOW}No log entries found.{Color.END}")
        return 0

    # Handle --shader-cache flag (Shader cache management)
    if getattr(args, 'shader_cache', None) is not None:
        steam_root = find_steam_root()
        if not steam_root:
            if args.json:
                print(json.dumps({"error": "Steam not found"}, indent=2))
            else:
                print(f"{Color.RED}✗ Steam not found{Color.END}")
            return 1

        action = args.shader_cache.lower() if args.shader_cache else 'list'

        if action == 'list':
            caches = scan_shader_caches(steam_root)

            if args.json:
                output = {
                    "caches": [
                        {
                            "app_id": c.app_id,
                            "name": c.name,
                            "path": c.cache_path,
                            "size_mb": round(c.size_bytes / (1024 * 1024), 1),
                            "file_count": c.file_count,
                            "last_modified": c.last_modified,
                        }
                        for c in caches
                    ],
                    "total_size_mb": round(sum(c.size_bytes for c in caches) / (1024 * 1024), 1)
                }
                print(json.dumps(output, indent=2))
            elif caches:
                total_size = sum(c.size_bytes for c in caches)
                print(f"\n{Color.BOLD}Shader Caches{Color.END} ({len(caches)} games, {total_size / (1024**2):.0f} MB total)\n")

                for c in sorted(caches, key=lambda x: x.size_bytes, reverse=True)[:20]:
                    size_mb = c.size_bytes / (1024**2)
                    print(f"  {c.name or c.app_id:<40} {size_mb:>8.1f} MB  ({c.file_count} files)")

                print(f"\n{Color.DIM}Clear with: --shader-cache clear <appid|all>{Color.END}")
            else:
                print(f"{Color.YELLOW}No shader caches found.{Color.END}")

        elif action.startswith('clear'):
            # Parse: clear all or clear <appid>
            parts = action.split()
            target = parts[1] if len(parts) > 1 else 'all'

            if target == 'all':
                cleared, total = clear_all_shader_caches(steam_root)
                print(f"{Color.GREEN}✓ Cleared {cleared} shader caches ({total / (1024**2):.0f} MB){Color.END}")
            else:
                success, cleared_bytes = clear_shader_cache(steam_root, target)
                if success:
                    print(f"{Color.GREEN}✓ Cleared shader cache for {target} ({cleared_bytes / (1024**2):.0f} MB){Color.END}")
                else:
                    print(f"{Color.RED}✗ Shader cache not found for {target}{Color.END}")
                    return 1
        else:
            print(f"{Color.RED}Unknown shader-cache action: {action}{Color.END}")
            print("Use: --shader-cache list, --shader-cache clear <appid|all>")
            return 1
        return 0

    # Handle --compatdata flag (Wine prefix backup/restore)
    if getattr(args, 'compatdata', None) is not None:
        steam_root = find_steam_root()
        if not steam_root:
            if args.json:
                print(json.dumps({"error": "Steam not found"}, indent=2))
            else:
                print(f"{Color.RED}✗ Steam not found{Color.END}")
            return 1

        action = args.compatdata.lower() if args.compatdata else 'list'
        backup_dir = args.backup_dir or os.path.expanduser('~/.local/share/steam-proton-helper/backups')

        if action == 'list':
            prefixes = scan_compatdata(steam_root)

            if args.json:
                output = {
                    "prefixes": [
                        {
                            "app_id": p.app_id,
                            "name": p.name,
                            "path": p.path,
                            "size_mb": round(p.size_bytes / (1024 * 1024), 1),
                            "last_modified": p.last_modified,
                            "proton_version": p.proton_version,
                        }
                        for p in prefixes
                    ],
                    "total_size_mb": round(sum(p.size_bytes for p in prefixes) / (1024 * 1024), 1)
                }
                print(json.dumps(output, indent=2))
            elif prefixes:
                total_size = sum(p.size_bytes for p in prefixes)
                print(f"\n{Color.BOLD}Wine Prefixes (compatdata){Color.END} ({len(prefixes)} games, {total_size / (1024**3):.1f} GB total)\n")

                for p in sorted(prefixes, key=lambda x: x.size_bytes, reverse=True)[:20]:
                    size_gb = p.size_bytes / (1024**3)
                    name = p.name or p.app_id
                    print(f"  {name:<40} {size_gb:>6.1f} GB")
                    if args.verbose:
                        print(f"    {Color.DIM}AppID: {p.app_id}  Proton: {p.proton_version or 'unknown'}{Color.END}")

                print(f"\n{Color.DIM}Backup with: --compatdata backup <appid>{Color.END}")
            else:
                print(f"{Color.YELLOW}No Wine prefixes found.{Color.END}")

        elif action == 'backups':
            backups = list_compatdata_backups(backup_dir)

            if args.json:
                print(json.dumps({"backups": backups}, indent=2))
            elif backups:
                print(f"\n{Color.BOLD}Available Backups{Color.END}\n")
                for b in backups:
                    size_mb = b['size_bytes'] / (1024**2)
                    print(f"  {b['filename']:<50} {size_mb:>8.1f} MB  {b['created']}")

                print(f"\n{Color.DIM}Restore with: --compatdata restore <appid>{Color.END}")
            else:
                print(f"{Color.YELLOW}No backups found in {backup_dir}{Color.END}")

        elif action.startswith('backup'):
            parts = action.split()
            if len(parts) < 2:
                print(f"{Color.RED}Usage: --compatdata 'backup <appid>'{Color.END}")
                return 1
            app_id = parts[1]

            print(f"Backing up Wine prefix for AppID {app_id}...")
            success, result = backup_compatdata(steam_root, app_id, backup_dir)
            if success:
                print(f"{Color.GREEN}✓ Backup created: {result}{Color.END}")
            else:
                print(f"{Color.RED}✗ {result}{Color.END}")
                return 1

        elif action.startswith('restore'):
            parts = action.split()
            if len(parts) < 2:
                print(f"{Color.RED}Usage: --compatdata 'restore <appid>'{Color.END}")
                return 1
            app_id = parts[1]

            print(f"Restoring Wine prefix for AppID {app_id}...")
            success, result = restore_compatdata(steam_root, app_id, backup_dir)
            if success:
                print(f"{Color.GREEN}✓ {result}{Color.END}")
            else:
                print(f"{Color.RED}✗ {result}{Color.END}")
                return 1

        else:
            print(f"{Color.RED}Unknown compatdata action: {action}{Color.END}")
            print("Use: --compatdata list, --compatdata backups, --compatdata 'backup <appid>', --compatdata 'restore <appid>'")
            return 1
        return 0

    # Handle --profile flag (Game launch profiles)
    if getattr(args, 'profile', None) is not None:
        action = args.profile.lower() if args.profile else 'list'

        if action == 'list':
            profiles = load_launch_profiles()

            if args.json:
                output = {
                    "profiles": {app_id: p.to_dict() for app_id, p in profiles.items()}
                }
                print(json.dumps(output, indent=2))
            elif profiles:
                print(f"\n{Color.BOLD}Game Launch Profiles{Color.END} ({len(profiles)} profiles)\n")

                for app_id, p in profiles.items():
                    features = []
                    if p.mangohud:
                        features.append("MangoHud")
                    if p.gamemode:
                        features.append("GameMode")
                    if p.proton_version:
                        features.append(f"Proton: {p.proton_version}")

                    features_str = f" ({', '.join(features)})" if features else ""
                    print(f"  {p.name or app_id}{features_str}")
                    print(f"    AppID: {app_id}")
                    if p.launch_options:
                        print(f"    Launch: {p.launch_options}")
                    if args.verbose:
                        cmd = generate_launch_command(p)
                        print(f"    {Color.DIM}Full command: {cmd}{Color.END}")
            else:
                print(f"{Color.YELLOW}No launch profiles configured.{Color.END}")
                print(f"\n{Color.DIM}Create with: --profile 'set <appid>' --profile-mangohud --profile-gamemode{Color.END}")

        elif action.startswith('get'):
            parts = action.split()
            if len(parts) < 2:
                print(f"{Color.RED}Usage: --profile 'get <appid>'{Color.END}")
                return 1
            app_id = parts[1]

            profile = get_launch_profile(app_id)
            if profile:
                if args.json:
                    print(json.dumps(profile.to_dict(), indent=2))
                else:
                    print(f"\n{Color.BOLD}Profile for {profile.name or app_id}{Color.END}\n")
                    print(f"  Proton: {profile.proton_version or 'default'}")
                    print(f"  MangoHud: {'enabled' if profile.mangohud else 'disabled'}")
                    print(f"  GameMode: {'enabled' if profile.gamemode else 'disabled'}")
                    if profile.launch_options:
                        print(f"  Launch options: {profile.launch_options}")
                    if profile.env_vars:
                        print(f"  Environment:")
                        for k, v in profile.env_vars.items():
                            print(f"    {k}={v}")
                    print(f"\n  {Color.DIM}Steam launch command:{Color.END}")
                    print(f"  {generate_launch_command(profile)}")
            else:
                print(f"{Color.YELLOW}No profile found for AppID {app_id}{Color.END}")
                return 1

        elif action.startswith('set'):
            parts = action.split()
            if len(parts) < 2:
                print(f"{Color.RED}Usage: --profile 'set <appid>' [options]{Color.END}")
                return 1
            app_id = parts[1]

            # Get existing profile or create new one
            profile = get_launch_profile(app_id) or GameLaunchProfile(
                app_id=app_id,
                name=f"Game {app_id}",
            )

            # Update from CLI args
            if args.profile_proton:
                profile.proton_version = args.profile_proton
            if args.profile_options:
                profile.launch_options = args.profile_options
            if args.profile_mangohud:
                profile.mangohud = True
            if args.profile_gamemode:
                profile.gamemode = True

            if set_launch_profile(profile):
                print(f"{Color.GREEN}✓ Profile saved for AppID {app_id}{Color.END}")
                print(f"\n  {Color.DIM}Steam launch command:{Color.END}")
                print(f"  {generate_launch_command(profile)}")
            else:
                print(f"{Color.RED}✗ Failed to save profile{Color.END}")
                return 1

        elif action.startswith('delete'):
            parts = action.split()
            if len(parts) < 2:
                print(f"{Color.RED}Usage: --profile 'delete <appid>'{Color.END}")
                return 1
            app_id = parts[1]

            if delete_launch_profile(app_id):
                print(f"{Color.GREEN}✓ Profile deleted for AppID {app_id}{Color.END}")
            else:
                print(f"{Color.YELLOW}No profile found for AppID {app_id}{Color.END}")
                return 1

        else:
            print(f"{Color.RED}Unknown profile action: {action}{Color.END}")
            print("Use: --profile list, --profile 'get <appid>', --profile 'set <appid>', --profile 'delete <appid>'")
            return 1
        return 0

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
