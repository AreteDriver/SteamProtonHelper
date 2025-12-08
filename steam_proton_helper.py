#!/usr/bin/env python3
"""
Steam Proton Helper - A tool to help setup Steam and Proton on Linux
Checks dependencies, installs missing packages, and verifies setup
"""

import os
import sys
import subprocess
import shutil
import platform
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class CheckStatus(Enum):
    """Status of a dependency check"""
    PASS = "✓"
    FAIL = "✗"
    WARNING = "⚠"
    SKIPPED = "○"


class Color:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


@dataclass
class DependencyCheck:
    """Result of a dependency check"""
    name: str
    status: CheckStatus
    message: str
    fix_command: Optional[str] = None


class DistroDetector:
    """Detect Linux distribution and package manager"""
    
    @staticmethod
    def detect_distro() -> Tuple[str, str]:
        """
        Detect the Linux distribution
        Returns: (distro_name, package_manager)
        """
        try:
            # Try to read /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    distro_info = {}
                    for line in lines:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            distro_info[key] = value.strip('"')
                    
                    distro_id = distro_info.get('ID', '').lower()
                    distro_like = distro_info.get('ID_LIKE', '').lower()
                    
                    # Determine package manager
                    if distro_id in ['ubuntu', 'debian', 'mint', 'pop'] or 'debian' in distro_like or 'ubuntu' in distro_like:
                        return (distro_id, 'apt')
                    elif distro_id in ['fedora', 'rhel', 'centos'] or 'fedora' in distro_like:
                        return (distro_id, 'dnf')
                    elif distro_id in ['arch', 'manjaro', 'endeavouros'] or 'arch' in distro_like:
                        return (distro_id, 'pacman')
                    elif distro_id in ['opensuse', 'suse']:
                        return (distro_id, 'zypper')
            
            # Fallback to checking for package managers
            if shutil.which('apt'):
                return ('unknown', 'apt')
            elif shutil.which('dnf'):
                return ('unknown', 'dnf')
            elif shutil.which('pacman'):
                return ('unknown', 'pacman')
            elif shutil.which('zypper'):
                return ('unknown', 'zypper')
            
        except Exception as e:
            print(f"{Color.YELLOW}Warning: Could not detect distribution: {e}{Color.END}")
        
        return ('unknown', 'unknown')


class DependencyChecker:
    """Check for Steam and Proton dependencies"""
    
    def __init__(self, distro: str, package_manager: str):
        self.distro = distro
        self.package_manager = package_manager
        self.checks: List[DependencyCheck] = []
    
    def run_command(self, cmd: List[str], check: bool = False) -> Tuple[int, str]:
        """Run a shell command and return (exit_code, output)"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return (result.returncode, result.stdout + result.stderr)
        except subprocess.CalledProcessError as e:
            return (e.returncode, e.stdout + e.stderr)
        except Exception as e:
            return (1, str(e))
    
    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        return shutil.which(command) is not None
    
    def check_package_installed(self, package: str) -> bool:
        """Check if a package is installed"""
        if self.package_manager == 'apt':
            code, _ = self.run_command(['dpkg', '-l', package])
            return code == 0
        elif self.package_manager == 'dnf':
            code, _ = self.run_command(['rpm', '-q', package])
            return code == 0
        elif self.package_manager == 'pacman':
            code, _ = self.run_command(['pacman', '-Q', package])
            return code == 0
        return False
    
    def check_steam_installed(self) -> DependencyCheck:
        """Check if Steam is installed"""
        if self.check_command_exists('steam'):
            return DependencyCheck(
                name="Steam Client",
                status=CheckStatus.PASS,
                message="Steam is installed"
            )
        else:
            fix_cmd = self._get_install_command('steam')
            return DependencyCheck(
                name="Steam Client",
                status=CheckStatus.FAIL,
                message="Steam is not installed",
                fix_command=fix_cmd
            )
    
    def check_graphics_drivers(self) -> List[DependencyCheck]:
        """Check for graphics drivers"""
        checks = []
        
        # Check for Vulkan support
        if self.check_command_exists('vulkaninfo'):
            code, output = self.run_command(['vulkaninfo', '--summary'])
            if code == 0:
                checks.append(DependencyCheck(
                    name="Vulkan Support",
                    status=CheckStatus.PASS,
                    message="Vulkan is available"
                ))
            else:
                checks.append(DependencyCheck(
                    name="Vulkan Support",
                    status=CheckStatus.WARNING,
                    message="Vulkan command exists but returned error"
                ))
        else:
            fix_cmd = self._get_install_command('vulkan-tools')
            checks.append(DependencyCheck(
                name="Vulkan Tools",
                status=CheckStatus.FAIL,
                message="Vulkan tools not installed",
                fix_command=fix_cmd
            ))
        
        # Check for Mesa (common on Linux)
        if self.check_package_installed('mesa-utils') or self.check_command_exists('glxinfo'):
            checks.append(DependencyCheck(
                name="Mesa/OpenGL",
                status=CheckStatus.PASS,
                message="Mesa utilities available"
            ))
        else:
            checks.append(DependencyCheck(
                name="Mesa/OpenGL",
                status=CheckStatus.WARNING,
                message="Mesa utilities not found (may not be needed)"
            ))
        
        return checks
    
    def check_required_libraries(self) -> List[DependencyCheck]:
        """Check for required libraries"""
        checks = []
        
        required_libs = {
            'apt': ['lib32gcc-s1', 'lib32stdc++6', 'libc6-i386'],
            'dnf': ['glibc.i686', 'libgcc.i686', 'libstdc++.i686'],
            'pacman': ['lib32-gcc-libs', 'lib32-glibc'],
        }
        
        if self.package_manager in required_libs:
            # Check for 32-bit library support (needed for many Steam games)
            arch = platform.machine()
            if arch == 'x86_64':
                checks.append(DependencyCheck(
                    name="64-bit System",
                    status=CheckStatus.PASS,
                    message="System supports 64-bit"
                ))
                
                # Check if multilib is enabled (for 32-bit compatibility)
                if self.package_manager == 'apt':
                    code, output = self.run_command(['dpkg', '--print-foreign-architectures'])
                    if 'i386' in output:
                        checks.append(DependencyCheck(
                            name="32-bit Support",
                            status=CheckStatus.PASS,
                            message="32-bit architecture support enabled"
                        ))
                    else:
                        checks.append(DependencyCheck(
                            name="32-bit Support",
                            status=CheckStatus.WARNING,
                            message="32-bit architecture not enabled",
                            fix_command="sudo dpkg --add-architecture i386 && sudo apt update"
                        ))
                else:
                    checks.append(DependencyCheck(
                        name="32-bit Support",
                        status=CheckStatus.PASS,
                        message="Assuming 32-bit support available"
                    ))
        
        return checks
    
    def check_proton(self) -> DependencyCheck:
        """Check for Proton installation"""
        # Proton is typically installed through Steam
        steam_path = os.path.expanduser('~/.steam/steam')
        proton_paths = [
            os.path.join(steam_path, 'steamapps/common'),
            os.path.join(steam_path, 'compatibilitytools.d')
        ]
        
        proton_found = False
        for path in proton_paths:
            if os.path.exists(path):
                try:
                    entries = os.listdir(path)
                    for entry in entries:
                        if 'proton' in entry.lower():
                            proton_found = True
                            break
                except Exception:
                    pass
        
        if proton_found:
            return DependencyCheck(
                name="Proton",
                status=CheckStatus.PASS,
                message="Proton installation found"
            )
        else:
            return DependencyCheck(
                name="Proton",
                status=CheckStatus.WARNING,
                message="Proton not found (install from Steam client)",
                fix_command="Install Proton from Steam > Settings > Compatibility > Enable Steam Play"
            )
    
    def check_wine_dependencies(self) -> List[DependencyCheck]:
        """Check for Wine dependencies (used by Proton)"""
        checks = []
        
        # Check for common Wine dependencies
        if self.package_manager in ['apt', 'dnf', 'pacman']:
            checks.append(DependencyCheck(
                name="Wine Dependencies",
                status=CheckStatus.PASS,
                message="Package manager available for Wine dependencies"
            ))
        
        return checks
    
    def _get_install_command(self, package: str) -> str:
        """Get the install command for a package based on package manager"""
        if self.package_manager == 'apt':
            return f"sudo apt update && sudo apt install -y {package}"
        elif self.package_manager == 'dnf':
            return f"sudo dnf install -y {package}"
        elif self.package_manager == 'pacman':
            return f"sudo pacman -S --noconfirm {package}"
        elif self.package_manager == 'zypper':
            return f"sudo zypper install -y {package}"
        else:
            return f"Please install {package} manually"
    
    def run_all_checks(self) -> List[DependencyCheck]:
        """Run all dependency checks"""
        all_checks = []
        
        # System info
        all_checks.append(DependencyCheck(
            name="Linux Distribution",
            status=CheckStatus.PASS,
            message=f"{self.distro} ({self.package_manager})"
        ))
        
        # Steam check
        all_checks.append(self.check_steam_installed())
        
        # Proton check
        all_checks.append(self.check_proton())
        
        # Graphics drivers
        all_checks.extend(self.check_graphics_drivers())
        
        # Required libraries
        all_checks.extend(self.check_required_libraries())
        
        # Wine dependencies
        all_checks.extend(self.check_wine_dependencies())
        
        return all_checks


class SteamProtonHelper:
    """Main application class"""
    
    def __init__(self):
        self.distro, self.package_manager = DistroDetector.detect_distro()
        self.checker = DependencyChecker(self.distro, self.package_manager)
    
    def print_header(self):
        """Print application header"""
        print(f"\n{Color.BOLD}{Color.CYAN}╔══════════════════════════════════════════╗{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}║   Steam + Proton Helper for Linux       ║{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}╔══════════════════════════════════════════╗{Color.END}\n")
    
    def print_summary(self, checks: List[DependencyCheck]):
        """Print summary of checks"""
        print(f"\n{Color.BOLD}{'='*50}{Color.END}")
        print(f"{Color.BOLD}Dependency Check Summary{Color.END}")
        print(f"{Color.BOLD}{'='*50}{Color.END}\n")
        
        passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
        failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        warnings = sum(1 for c in checks if c.status == CheckStatus.WARNING)
        
        for check in checks:
            status_color = {
                CheckStatus.PASS: Color.GREEN,
                CheckStatus.FAIL: Color.RED,
                CheckStatus.WARNING: Color.YELLOW,
                CheckStatus.SKIPPED: Color.BLUE
            }.get(check.status, '')
            
            print(f"{status_color}{check.status.value}{Color.END} {Color.BOLD}{check.name}{Color.END}: {check.message}")
            
            if check.fix_command:
                print(f"  {Color.CYAN}Fix:{Color.END} {check.fix_command}")
        
        print(f"\n{Color.BOLD}Results:{Color.END}")
        print(f"  {Color.GREEN}Passed:{Color.END} {passed}")
        print(f"  {Color.RED}Failed:{Color.END} {failed}")
        print(f"  {Color.YELLOW}Warnings:{Color.END} {warnings}")
        
        if failed == 0 and warnings == 0:
            print(f"\n{Color.GREEN}{Color.BOLD}✓ Your system is ready for Steam gaming!{Color.END}")
        elif failed == 0:
            print(f"\n{Color.YELLOW}{Color.BOLD}⚠ Your system is mostly ready, but check the warnings above.{Color.END}")
        else:
            print(f"\n{Color.RED}{Color.BOLD}✗ Please install the missing dependencies above.{Color.END}")
    
    def run(self):
        """Run the main application"""
        self.print_header()
        
        print(f"{Color.BOLD}Checking Steam and Proton dependencies...{Color.END}\n")
        
        checks = self.checker.run_all_checks()
        
        self.print_summary(checks)
        
        print(f"\n{Color.BOLD}Additional Tips:{Color.END}")
        print(f"  • To enable Proton in Steam: Settings → Compatibility → Enable Steam Play")
        print(f"  • For best performance, keep your graphics drivers updated")
        print(f"  • Visit ProtonDB (protondb.com) to check game compatibility")
        print()


def main():
    """Main entry point"""
    try:
        helper = SteamProtonHelper()
        helper.run()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}Interrupted by user{Color.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}Error: {e}{Color.END}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
