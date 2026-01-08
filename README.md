# Steam Proton Helper

[![PyPI version](https://img.shields.io/pypi/v/steam-proton-helper)](https://pypi.org/project/steam-proton-helper/)
[![Python versions](https://img.shields.io/pypi/pyversions/steam-proton-helper)](https://pypi.org/project/steam-proton-helper/)
[![CI](https://github.com/AreteDriver/SteamProtonHelper/actions/workflows/ci.yml/badge.svg)](https://github.com/AreteDriver/SteamProtonHelper/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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
- Python 3.8 or higher
- Terminal access

### Installation

#### Option 1: Install via pip (Recommended)
```bash
# CLI only
pip install steam-proton-helper

# CLI + GUI
pip install steam-proton-helper[gui]

# Or with pipx (for isolated install)
pipx install steam-proton-helper
```

#### Option 2: Clone and run directly
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
chmod +x steam_proton_helper.py
```

#### Option 3: Use the installation script
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
./install.sh
```

### GUI

Steam Proton Helper includes a full PyQt6 GUI with three tabs:

- **System Checks**: Visual tree view of all checks with status icons
- **Proton Management**: Install/update GE-Proton versions
- **ProtonDB Lookup**: Search game compatibility by name or AppID

```bash
# Launch GUI
steam-proton-helper-gui
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
usage: steam_proton_helper.py [-h] [--version] [--json] [--no-color] [--verbose]
                              [--fix [FILE]] [--apply] [--dry-run] [--yes]
                              [--game NAME] [--search QUERY] [--list-proton]
                              [--install-proton VERSION] [--force]
                              [--remove-proton VERSION] [--update-proton]
                              [--check-updates] [--recommend GAME] [--list-games]
                              [--profile [ACTION]] [--profile-proton VERSION]
                              [--profile-options OPTIONS] [--profile-mangohud]
                              [--profile-gamemode] [--shader-cache [ACTION]]
                              [--compatdata [ACTION]] [--backup-dir DIR]
                              [--perf-tools] [--logs [TYPE]] [--log-lines N]

Steam Proton Helper - Check system readiness for Steam gaming on Linux.

Core Options:
  -h, --help            Show this help message and exit
  --version, -V         Show program's version number and exit
  --json                Output results as machine-readable JSON
  --no-color            Disable ANSI color codes in output
  --verbose, -v         Show verbose/debug output including paths tried

Fix & Install:
  --fix [FILE]          Generate a shell script with fix commands (stdout or file)
  --apply               Auto-install missing packages (prompts for confirmation)
  --dry-run             Show what --apply would install without executing
  --yes, -y             Skip confirmation prompt (use with --apply)

ProtonDB & Game Search:
  --game NAME           Check ProtonDB compatibility by game name or AppID
  --search QUERY        Search Steam for games (returns AppIDs, no ProtonDB lookup)
  --recommend GAME      Recommend best Proton version based on ProtonDB reports
  --list-games          List installed Steam games with their Proton versions

Proton Management:
  --list-proton         List all detected Proton installations
  --install-proton VERSION  Install GE-Proton (use "latest" or "list")
  --remove-proton VERSION   Remove a custom Proton version
  --update-proton       Update all GE-Proton versions to latest
  --check-updates       Check if newer GE-Proton versions are available
  --force               Force reinstall if already installed

Game Profiles:
  --profile [ACTION]    Manage launch profiles: list, get, set, delete
  --profile-proton VERSION   Proton version for profile
  --profile-options OPTIONS  Launch options for profile
  --profile-mangohud    Enable MangoHud for profile
  --profile-gamemode    Enable GameMode for profile

Maintenance:
  --shader-cache [ACTION]    Manage shader caches: list, clear <appid|all>
  --compatdata [ACTION]      Manage Wine prefixes: list, backup, restore, backups
  --backup-dir DIR           Directory for compatdata backups
  --perf-tools               Check status of gaming performance tools
  --logs [TYPE]              View logs: all, errors, steam, proton, dxvk
  --log-lines N              Number of log entries to show (default: 50)
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

# Check ProtonDB compatibility by game name
./steam_proton_helper.py --game "elden ring"
./steam_proton_helper.py --game "The Witcher 3: Wild Hunt"

# Or by Steam AppID
./steam_proton_helper.py --game 292030    # The Witcher 3
./steam_proton_helper.py --game 1245620   # Elden Ring

# Check multiple games at once
./steam_proton_helper.py --game "elden ring" --game "baldurs gate 3"
./steam_proton_helper.py --game "292030,1245620"  # Comma-separated AppIDs

# Get ProtonDB info as JSON
./steam_proton_helper.py --game "elden ring" --json
./steam_proton_helper.py --game 292030 --game 1245620 --json  # Batch JSON

# Search Steam for games (get AppIDs without ProtonDB lookup)
./steam_proton_helper.py --search "witcher"
./steam_proton_helper.py --search "souls" --json

# List all installed Proton versions
./steam_proton_helper.py --list-proton
./steam_proton_helper.py --list-proton --verbose  # Show full paths
./steam_proton_helper.py --list-proton --json     # JSON output

# Install GE-Proton
./steam_proton_helper.py --install-proton list    # See available versions
./steam_proton_helper.py --install-proton latest  # Install latest
./steam_proton_helper.py --install-proton GE-Proton10-26  # Specific version
./steam_proton_helper.py --install-proton latest --force  # Reinstall
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (may have warnings) |
| 1 | One or more checks failed |
| 130 | Interrupted by user (Ctrl+C) |

### Shell Completions

Tab completion is available for Bash, Zsh, and Fish. Install via `./install.sh` or manually:

**Bash:**
```bash
cp completions/steam-proton-helper.bash ~/.local/share/bash-completion/completions/steam-proton-helper
```

**Zsh:** (add `~/.zsh/completions` to your `$fpath` in `.zshrc`)
```bash
mkdir -p ~/.zsh/completions
cp completions/_steam-proton-helper ~/.zsh/completions/
```

**Fish:**
```bash
cp completions/steam-proton-helper.fish ~/.config/fish/completions/
```

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

### ProtonDB Integration

Use `--game` to check game compatibility on ProtonDB. You can search by name or AppID:

```bash
# Search by game name
./steam_proton_helper.py --game "elden ring"

# Or use Steam AppID directly
./steam_proton_helper.py --game 292030
```

Output:
```
Found: ELDEN RING (AppID: 1245620)

ProtonDB Compatibility for AppID 1245620
────────────────────────────────────────────
  🥇 Rating: GOLD
  📊 Score: 0.77
  📝 Reports: 1935
  🎯 Confidence: strong
  ⭐ Best Reported: PLATINUM
  📈 Trending: PLATINUM

  ℹ️  Runs perfectly after tweaks

  🔗 https://www.protondb.com/app/1245620
```

If multiple games match your search, you'll see a list:
```
Multiple games found for 'witcher':

  1. The Witcher 3: Wild Hunt (AppID: 292030)
  2. The Witcher 2: Assassins of Kings (AppID: 20920)
  3. The Witcher: Enhanced Edition (AppID: 20900)

Use --game <AppID> for the specific game.
```

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
python3 --version  # Requires 3.8+

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

## Custom Proton Versions

Steam Proton Helper automatically detects custom Proton builds installed in `compatibilitytools.d`. Here's how to install and manage them.

### Installing GE-Proton (Recommended)

[GE-Proton](https://github.com/GloriousEggroll/proton-ge-custom) is the most popular custom Proton build with additional patches and fixes.

**Manual Installation:**
```bash
# Create the compatibility tools directory
mkdir -p ~/.steam/root/compatibilitytools.d

# Download latest GE-Proton (check GitHub for current version)
cd /tmp
wget https://github.com/GloriousEggroll/proton-ge-custom/releases/download/GE-Proton9-22/GE-Proton9-22.tar.gz

# Extract to Steam's compatibility tools directory
tar -xzf GE-Proton9-22.tar.gz -C ~/.steam/root/compatibilitytools.d/

# Restart Steam to detect the new Proton version
```

**Using ProtonUp-Qt (Easier):**
```bash
# Install ProtonUp-Qt
flatpak install flathub net.davidotek.pupgui2

# Run and select GE-Proton versions to install
flatpak run net.davidotek.pupgui2
```

### Custom Proton Locations

Steam looks for custom Proton builds in these directories:

| Steam Type | Path |
|------------|------|
| Native | `~/.steam/root/compatibilitytools.d/` |
| Native (alt) | `~/.local/share/Steam/compatibilitytools.d/` |
| Flatpak | `~/.var/app/com.valvesoftware.Steam/data/Steam/compatibilitytools.d/` |

### Other Custom Proton Builds

| Build | Description | Link |
|-------|-------------|------|
| GE-Proton | Patches for better game compatibility | [GitHub](https://github.com/GloriousEggroll/proton-ge-custom) |
| Proton-TKG | Highly configurable, build-your-own | [GitHub](https://github.com/Frogging-Family/wine-tkg-git) |
| Proton Experimental | Valve's bleeding-edge builds | Steam Library → Tools |

### Selecting Proton Version Per-Game

1. Right-click the game in Steam → **Properties**
2. Go to **Compatibility** tab
3. Check **"Force the use of a specific Steam Play compatibility tool"**
4. Select your preferred Proton version from the dropdown

## Steam Launch Options

Launch options let you customize how games run. Set them via:
**Right-click game → Properties → General → Launch Options**

### Common Launch Options

| Option | Description |
|--------|-------------|
| `PROTON_USE_WINED3D=1 %command%` | Use OpenGL instead of Vulkan (for older GPUs) |
| `PROTON_NO_ESYNC=1 %command%` | Disable esync (fixes some crashes) |
| `PROTON_NO_FSYNC=1 %command%` | Disable fsync (fixes some crashes) |
| `DXVK_HUD=fps %command%` | Show FPS counter |
| `DXVK_HUD=full %command%` | Show full DXVK stats overlay |
| `mangohud %command%` | Use MangoHud overlay (if installed) |
| `gamemoderun %command%` | Enable GameMode optimizations (if installed) |
| `PROTON_LOG=1 %command%` | Enable Proton logging for debugging |
| `WINEDEBUG=-all %command%` | Suppress Wine debug output |

### Performance Launch Options

```bash
# Maximum performance (combine as needed)
gamemoderun mangohud %command%

# For AMD GPUs - enable ACO shader compiler
RADV_PERFTEST=aco %command%

# Limit FPS to reduce heat/power
DXVK_FRAME_RATE=60 %command%

# Use specific GPU (multi-GPU systems)
DRI_PRIME=1 %command%
```

### Troubleshooting Launch Options

```bash
# Game crashes on startup - try disabling sync
PROTON_NO_ESYNC=1 PROTON_NO_FSYNC=1 %command%

# Black screen or rendering issues
PROTON_USE_WINED3D=1 %command%

# Enable verbose logging
PROTON_LOG=1 WINEDEBUG=+loaddll %command%

# Skip launcher/intro videos (game-specific)
%command% -skipintro -novid
```

### Game-Specific Examples

```bash
# Elden Ring - common fixes
PROTON_NO_FSYNC=1 %command%

# Cyberpunk 2077 - performance mode
gamemoderun mangohud DXVK_ASYNC=1 %command%

# Older DirectX 9 games
PROTON_USE_WINED3D=1 %command%

# Unity games with cursor issues
PROTON_USE_WINED3D=1 %command%
```

### Environment Variables Reference

| Variable | Values | Description |
|----------|--------|-------------|
| `PROTON_USE_WINED3D` | 0/1 | Use OpenGL instead of DXVK |
| `PROTON_NO_ESYNC` | 0/1 | Disable eventfd-based synchronization |
| `PROTON_NO_FSYNC` | 0/1 | Disable futex-based synchronization |
| `PROTON_FORCE_LARGE_ADDRESS_AWARE` | 0/1 | Force LAA for 32-bit games |
| `PROTON_OLD_GL_STRING` | 0/1 | Use old OpenGL version string |
| `PROTON_ENABLE_NVAPI` | 0/1 | Enable NVAPI for NVIDIA features |
| `DXVK_HUD` | fps/full/off | DXVK overlay settings |
| `DXVK_ASYNC` | 0/1 | Async shader compilation (reduces stutter) |
| `DXVK_FRAME_RATE` | number | Limit framerate |
| `MANGOHUD` | 0/1 | Enable MangoHud overlay |
| `WINE_FULLSCREEN_FSR` | 0/1 | Enable AMD FSR upscaling |
| `WINE_FULLSCREEN_FSR_STRENGTH` | 0-5 | FSR sharpening (0=max, 5=min) |

## Advanced Features (v2.3+)

### Game Launch Profiles

Create per-game launch profiles to store Proton versions and launch options:

```bash
# List all saved profiles
./steam_proton_helper.py --profile list

# Get profile for a specific game
./steam_proton_helper.py --profile get 1245620

# Set a profile with Proton version and options
./steam_proton_helper.py --profile set 1245620 \
  --profile-proton "GE-Proton9-22" \
  --profile-options "DXVK_ASYNC=1 %command%" \
  --profile-mangohud --profile-gamemode

# Delete a profile
./steam_proton_helper.py --profile delete 1245620
```

Profiles are stored in `~/.config/steam-proton-helper/profiles.json`.

### Shader Cache Management

Manage GPU shader caches to free disk space or fix shader-related issues:

```bash
# List shader caches with sizes
./steam_proton_helper.py --shader-cache list

# Clear shader cache for a specific game
./steam_proton_helper.py --shader-cache clear 1245620

# Clear all shader caches (use with caution)
./steam_proton_helper.py --shader-cache clear all
```

Supports both AMD (mesa) and NVIDIA shader cache locations.

### Compatdata (Wine Prefix) Backup & Restore

Backup and restore game Wine prefixes to preserve saves and settings:

```bash
# List all compatdata directories with sizes
./steam_proton_helper.py --compatdata list

# Backup a game's Wine prefix
./steam_proton_helper.py --compatdata backup 1245620

# List existing backups
./steam_proton_helper.py --compatdata backups

# Restore from backup
./steam_proton_helper.py --compatdata restore 1245620

# Use custom backup directory
./steam_proton_helper.py --compatdata backup 1245620 --backup-dir /mnt/backup/steam
```

Backups are compressed with gzip and stored in `~/.local/share/steam-proton-helper/backups/` by default.

### Installed Games List

View all installed Steam games and their configured Proton versions:

```bash
# List installed games
./steam_proton_helper.py --list-games

# JSON output for scripting
./steam_proton_helper.py --list-games --json
```

Parses ACF manifest files to detect installed games across all Steam libraries.

### Performance Tools Status

Check if gaming performance tools are installed and available:

```bash
# Check performance tools
./steam_proton_helper.py --perf-tools
```

Checks for: GameMode, MangoHud, vkBasalt, libstrangle, and OBS Game Capture.

### Log Viewer

View and filter Steam/Proton logs for troubleshooting:

```bash
# View all recent log entries
./steam_proton_helper.py --logs

# View only errors
./steam_proton_helper.py --logs errors

# View specific log type
./steam_proton_helper.py --logs steam
./steam_proton_helper.py --logs proton
./steam_proton_helper.py --logs dxvk

# Limit number of entries
./steam_proton_helper.py --logs errors --log-lines 100
```

### Proton Version Recommendations

Get Proton version recommendations based on ProtonDB reports:

```bash
# Get recommended Proton for a game
./steam_proton_helper.py --recommend "elden ring"
./steam_proton_helper.py --recommend 1245620
```

Analyzes ProtonDB reports to suggest the most successful Proton versions for each game.

## Resources

- [Steam for Linux](https://store.steampowered.com/linux)
- [Proton GitHub](https://github.com/ValveSoftware/Proton)
- [GE-Proton](https://github.com/GloriousEggroll/proton-ge-custom)
- [ProtonDB](https://www.protondb.com/)
- [ProtonUp-Qt](https://github.com/DavidoTek/ProtonUp-Qt)
- [Linux Gaming Wiki](https://linux-gaming.kwindu.eu/)

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is provided as-is for informational purposes. It does **not** install packages by default (use `--apply` to enable). Always review what will be installed with `--dry-run` before using `--apply`.
