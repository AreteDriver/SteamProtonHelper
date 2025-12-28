# Steam Proton Helper

A comprehensive Linux tool designed to streamline the setup and troubleshooting of Steam and Proton for gaming on Linux. This helper application automatically detects missing dependencies, validates system configurations, and provides actionable fixes to eliminate common barriers that prevent Windows games from running smoothly on Linux.

**Note:** This tool is a **read-only checker** by default. Use `--apply` to auto-install missing packages.

## Purpose

SteamProtonHelper serves as your **first-line diagnostic and setup assistant** for Linux gaming. It bridges the gap between a fresh Linux installation and a gaming-ready system by:

- **Automated Detection**: Identifying your Linux distribution and available package managers
- **Dependency Validation**: Checking for all required gaming components (Steam, Proton, graphics drivers, libraries)
- **Smart Remediation**: Providing distribution-specific commands to fix detected issues
- **System Verification**: Ensuring compatibility layers and runtime environments are properly configured

## Features

- **Steam Detection**: Detects Native, Flatpak, and Snap Steam installations
- **Proton Detection**: Finds official Proton and GE-Proton across all Steam libraries
- **Vulkan Verification**: Validates Vulkan support with actionable guidance
- **32-bit Support**: Checks multilib/i386 packages required for Windows games
- **Multi-Library Support**: Parses `libraryfolders.vdf` to check all Steam libraries
- **JSON Output**: Machine-readable output for scripting and automation
- **No External Dependencies**: Single-file Python script with stdlib only

## Supported Configurations

### Steam Installation Types

| Type | Detection Method | Status |
|------|-----------------|--------|
| Native | `steam` in PATH | Full support |
| Flatpak | `flatpak info com.valvesoftware.Steam` | Full support |
| Snap | `snap list steam` | Best-effort |

### Linux Distributions

| Distribution | Package Manager | 32-bit Check |
|-------------|-----------------|--------------|
| Ubuntu/Debian/Mint/Pop!_OS | apt | `dpkg --print-foreign-architectures`, per-package status |
| Fedora/RHEL/CentOS/Rocky | dnf | Automatic multilib, per-package status |
| Arch/Manjaro/EndeavourOS | pacman | `[multilib]` in pacman.conf, per-package status |
| openSUSE | zypper | Basic support |

## Quick Start

### Prerequisites
- Linux operating system (x86_64)
- Python 3.6 or higher
- Terminal access

### Installation

#### Option 1: Clone and run directly (Recommended)
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
chmod +x steam_proton_helper.py
```

#### Option 2: Install via pip
```bash
pip install git+https://github.com/AreteDriver/SteamProtonHelper.git
steam-proton-helper
```

#### Option 3: Use the installation script
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
./install.sh
```

### Basic Usage

```bash
# Run all checks with colored output
./steam_proton_helper.py

# Or with Python directly
python3 steam_proton_helper.py
```

## CLI Options

```
usage: steam_proton_helper.py [-h] [--json] [--no-color] [--verbose] [--fix [FILE]] [--apply] [--dry-run] [--yes]

Steam Proton Helper - Check system readiness for Steam gaming on Linux.

options:
  -h, --help     show this help message and exit
  --json         Output results as machine-readable JSON
  --no-color     Disable ANSI color codes in output
  --verbose, -v  Show verbose/debug output including paths tried
  --fix [FILE]   Generate a shell script with fix commands (stdout or file)
  --apply        Auto-install missing packages (prompts for confirmation)
  --dry-run      Show what --apply would install without executing
  --yes, -y      Skip confirmation prompt (use with --apply)
```

### Examples

```bash
# Standard check with colored output
./steam_proton_helper.py

# JSON output for scripting
./steam_proton_helper.py --json

# Generate fix script to stdout
./steam_proton_helper.py --fix

# Generate fix script to file
./steam_proton_helper.py --fix fix-steam.sh
# Then review and run: bash fix-steam.sh

# Preview what packages would be installed
./steam_proton_helper.py --dry-run

# Auto-install missing packages (with confirmation prompt)
./steam_proton_helper.py --apply

# Auto-install without confirmation (for scripting)
./steam_proton_helper.py --apply --yes

# Verbose mode to see all paths checked
./steam_proton_helper.py --verbose

# Disable colors (useful for piping)
./steam_proton_helper.py --no-color

# Combine options
./steam_proton_helper.py --json 2>/dev/null | jq '.summary'
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (may have warnings) |
| 1 | One or more checks failed |
| 130 | Interrupted by user (Ctrl+C) |

## What It Checks

### System
- Linux distribution and package manager
- System architecture (x86_64 recommended)

### Steam
- Steam client installation (native/flatpak/snap)
- Steam root directory location
- Steam library folders (from `libraryfolders.vdf`)

### Proton
- Official Proton installations in `steamapps/common`
- GE-Proton and custom Proton in `compatibilitytools.d`
- Validates presence of `proton` executable, `toolmanifest.vdf`, or `version` file

### Graphics
- **Vulkan**: Runs `vulkaninfo` and checks exit code
- **OpenGL**: Runs `glxinfo -B` if available

### 32-bit / Multilib
- Architecture support enabled (i386/multilib)
- Per-package status for critical 32-bit libraries:
  - **apt**: `libc6-i386`, `libstdc++6:i386`, `libvulkan1:i386`, `mesa-vulkan-drivers:i386`
  - **pacman**: `lib32-glibc`, `lib32-gcc-libs`, `lib32-vulkan-icd-loader`, `lib32-mesa`
  - **dnf**: `glibc.i686`, `libgcc.i686`, `libstdc++.i686`, `vulkan-loader.i686`

## Example Output

```
╔══════════════════════════════════════════╗
║   Steam + Proton Helper for Linux        ║
╚══════════════════════════════════════════╝

Checking Steam and Proton dependencies...

── System ──
  ✓ Linux Distribution: Ubuntu 24.04.1 LTS
  ✓ 64-bit System: x86_64 architecture

── Steam ──
  ✓ Steam Client: Installed: Native Steam in PATH
  ✓ Steam Root: /home/user/.local/share/Steam

── Proton ──
  ✓ Proton: Found 3 installation(s)

── Graphics ──
  ✓ Vulkan Support: Vulkan is available
  ✓ Mesa/OpenGL: OpenGL support available

── 32-bit ──
  ✓ Multilib/32-bit: i386 architecture enabled
  ✓ libc6-i386: Installed
  ✓ libstdc++6:i386: Installed
  ✓ libvulkan1:i386: Installed
  ✓ mesa-vulkan-drivers:i386: Installed

────────────────────────────────────────────
Summary
  Passed:   12
  Failed:   0
  Warnings: 0

✓ Your system is ready for Steam gaming!

Tips:
  • Enable Proton in Steam: Settings → Compatibility → Enable Steam Play
  • Keep graphics drivers updated for best performance
  • Check game compatibility at protondb.com
```

## JSON Output Format

```json
{
  "system": {
    "distro": "Ubuntu 24.04.1 LTS",
    "package_manager": "apt",
    "arch": "x86_64"
  },
  "steam": {
    "variant": "native",
    "message": "Native Steam in PATH",
    "root": "/home/user/.local/share/Steam",
    "libraries": ["/home/user/.local/share/Steam", "/mnt/games/SteamLibrary"]
  },
  "proton": {
    "found": true,
    "installations": [
      {
        "name": "Proton 9.0",
        "path": "/home/user/.local/share/Steam/steamapps/common/Proton 9.0",
        "has_executable": true,
        "has_toolmanifest": true,
        "has_version": true
      }
    ]
  },
  "checks": [...],
  "summary": {
    "passed": 12,
    "failed": 0,
    "warnings": 0,
    "skipped": 0
  }
}
```

## Common Issues and Fixes

### Steam Not Installed

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y steam
```

**Fedora:**
```bash
sudo dnf install -y steam
```

**Arch Linux:**
```bash
sudo pacman -S --noconfirm steam
```

### Missing Vulkan Support

If `vulkaninfo` fails, check:
1. GPU drivers are installed correctly
2. Vulkan ICD files exist (`/usr/share/vulkan/icd.d/`)
3. 32-bit Vulkan libraries are installed

**Ubuntu/Debian:**
```bash
sudo apt install -y vulkan-tools mesa-vulkan-drivers libvulkan1:i386
```

**Fedora:**
```bash
sudo dnf install -y vulkan-tools mesa-vulkan-drivers vulkan-loader.i686
```

**Arch Linux:**
```bash
sudo pacman -S --noconfirm vulkan-tools vulkan-icd-loader lib32-vulkan-icd-loader
```

### 32-bit Support Not Enabled

**Ubuntu/Debian:**
```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y libc6-i386 libstdc++6:i386 libvulkan1:i386
```

**Arch Linux:**
Enable `[multilib]` in `/etc/pacman.conf`:
```bash
sudo sed -i '/\[multilib\]/,/Include/s/^#//' /etc/pacman.conf
sudo pacman -Sy
sudo pacman -S --noconfirm lib32-glibc lib32-gcc-libs
```

### Proton Not Found

1. Open Steam
2. Go to **Settings** → **Compatibility**
3. Enable **"Enable Steam Play for supported titles"**
4. Optionally enable **"Enable Steam Play for all other titles"**
5. Select your preferred Proton version
6. Restart Steam

## Troubleshooting

### Script won't run
```bash
# Check Python version
python3 --version  # Requires 3.6+

# Make executable
chmod +x steam_proton_helper.py

# Run directly
python3 steam_proton_helper.py
```

### Steam installed but not detected
- For Flatpak: Ensure `flatpak` command is available
- For native: Check if `steam` is in your PATH
- Run with `--verbose` to see detection attempts

### VDF parsing fails
The script includes a minimal VDF parser. If `libraryfolders.vdf` has an unusual format:
- Run with `--verbose` to see parsing details
- The script will fall back to default paths

## Resources

- [Steam for Linux](https://store.steampowered.com/linux)
- [Proton GitHub](https://github.com/ValveSoftware/Proton)
- [GE-Proton](https://github.com/GloriousEggroll/proton-ge-custom)
- [ProtonDB](https://www.protondb.com/)
- [Linux Gaming Wiki](https://linux-gaming.kwindu.eu/)

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is provided as-is for informational purposes. It does **not** install packages by default (use `--apply` to enable). Always review what will be installed with `--dry-run` before using `--apply`.
