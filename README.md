# Steam Proton Helper 🎮

A comprehensive Linux tool designed to streamline the setup and troubleshooting of Steam and Proton for gaming on Linux. This helper application automatically detects missing dependencies, validates system configurations, and provides actionable fixes to eliminate common barriers that prevent Windows games from running smoothly on Linux.

## Purpose

SteamProtonHelper serves as your **first-line diagnostic and setup assistant** for Linux gaming. It bridges the gap between a fresh Linux installation and a gaming-ready system by:

- **Automated Detection**: Identifying your Linux distribution and available package managers
- **Dependency Validation**: Checking for all required gaming components (Steam, Proton, graphics drivers, libraries)
- **Smart Remediation**: Providing distribution-specific commands to fix detected issues
- **System Verification**: Ensuring compatibility layers and runtime environments are properly configured

## Problems Addressed

Linux gaming presents unique challenges that SteamProtonHelper specifically targets:

### 🎯 **Fragmented Setup Requirements**
Different Linux distributions require different packages and configurations. SteamProtonHelper eliminates guesswork by auto-detecting your system and providing the exact commands needed for your distribution.

### 🎯 **Missing Compatibility Layers**
Windows games require Proton (a Wine-based compatibility layer), but users often don't know:
- If Proton is installed
- Where to find it
- How to enable it in Steam
SteamProtonHelper verifies Proton installation and guides users through activation.

### 🎯 **Graphics Driver Complexity**
Modern games require Vulkan support and proper graphics drivers, which vary by GPU vendor (NVIDIA, AMD, Intel). SteamProtonHelper checks for:
- Vulkan runtime and tools
- Mesa/OpenGL libraries
- Distribution-specific driver packages

### 🎯 **32-bit Library Dependencies**
Many Windows games are 32-bit applications requiring multilib support on 64-bit Linux systems. SteamProtonHelper:
- Detects if 32-bit architecture support is enabled
- Provides commands to enable multilib repositories
- Verifies essential 32-bit libraries are installed

### 🎯 **Cryptic Error Messages**
When games fail to launch, Steam provides minimal diagnostics. SteamProtonHelper proactively identifies configuration gaps before you encounter runtime errors.

## Constraints Solved

### ⚙️ **Distribution-Agnostic Operation**
- **Constraint**: Package names and commands differ across Ubuntu, Fedora, Arch, openSUSE
- **Solution**: Auto-detects package manager (apt, dnf, pacman, zypper) and provides tailored installation commands

### ⚙️ **Permission and Access Requirements**
- **Constraint**: System modifications require sudo/root access
- **Solution**: Clearly displays commands requiring elevation, allowing users to review before executing

### ⚙️ **Hidden Installation Paths**
- **Constraint**: Proton installs in user-specific Steam directories that are difficult to locate
- **Solution**: Automatically searches standard Steam installation paths to verify Proton presence

### ⚙️ **Dependency Chain Complexity**
- **Constraint**: Gaming requires multiple interdependent components (Steam → Proton → Wine → Graphics Drivers → 32-bit libs)
- **Solution**: Checks entire dependency chain in logical order and reports status comprehensively

## Impact on Gaming Experience

### 🚀 **Faster Time-to-Game**
- **Before**: Hours of forum searching, trial-and-error installations, obscure error messages
- **After**: 2-3 minute automated check provides complete system status and fix commands

### 🚀 **Reduced Frustration**
- **Before**: "This game worked on Windows, why won't it run on Linux?"
- **After**: Clear diagnosis of missing components with specific remediation steps

### 🚀 **Confidence Building**
- **Before**: Uncertainty about whether Linux can handle gaming workloads
- **After**: Transparent view of system readiness and required optimizations

### 🚀 **Proactive Prevention**
- **Before**: Install game, encounter error, debug system
- **After**: Validate system configuration before purchasing/installing games

### 🚀 **Learning Aid**
- **Before**: Blindly copying commands from forums without understanding
- **After**: See exactly which components are needed and why they matter for gaming

## Features

✅ **Automatic Dependency Detection**
- Detects your Linux distribution and package manager
- Checks for Steam installation
- Verifies Proton compatibility layer
- Validates graphics drivers (Vulkan, Mesa/OpenGL)
- Ensures 32-bit library support for older games

✅ **Smart Troubleshooting**
- Provides specific fix commands for missing dependencies
- Color-coded output for easy identification of issues
- Helpful tips and recommendations

✅ **Distribution Support**
- Ubuntu/Debian (apt)
- Fedora/RHEL/CentOS (dnf)
- Arch/Manjaro (pacman)
- openSUSE (zypper)
- Auto-detection for other distributions

## Quick Start

### Prerequisites
- Linux operating system
- Python 3.6 or higher
- Terminal access

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
```

2. **Run the helper:**
```bash
python3 steam_proton_helper.py
```

Or make it executable and run directly:
```bash
chmod +x steam_proton_helper.py
./steam_proton_helper.py
```

## What It Checks

### 1. **System Information**
- Linux distribution detection
- Package manager identification

### 2. **Steam Client**
- Verifies Steam is installed
- Provides installation commands if missing

### 3. **Proton Compatibility Layer**
- Checks for Proton installation in Steam directories
- Guides you to enable Steam Play if needed

### 4. **Graphics Drivers**
- **Vulkan**: Modern graphics API required for many games
- **Mesa/OpenGL**: Essential graphics libraries

### 5. **32-bit Support**
- Verifies multilib/32-bit architecture support
- Critical for running older Windows games

### 6. **Wine Dependencies**
- Checks compatibility layer components used by Proton

## Example Output

```
╔══════════════════════════════════════════╗
║   Steam + Proton Helper for Linux       ║
╔══════════════════════════════════════════╗

Checking Steam and Proton dependencies...

==================================================
Dependency Check Summary
==================================================

✓ Linux Distribution: ubuntu (apt)
✓ Steam Client: Steam is installed
✓ Proton: Proton installation found
✓ Vulkan Support: Vulkan is available
✓ Mesa/OpenGL: Mesa utilities available
✓ 64-bit System: System supports 64-bit
✓ 32-bit Support: 32-bit architecture support enabled
✓ Wine Dependencies: Package manager available for Wine dependencies

Results:
  Passed: 8
  Failed: 0
  Warnings: 0

✓ Your system is ready for Steam gaming!

Additional Tips:
  • To enable Proton in Steam: Settings → Compatibility → Enable Steam Play
  • For best performance, keep your graphics drivers updated
  • Visit ProtonDB (protondb.com) to check game compatibility
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

**Ubuntu/Debian:**
```bash
sudo apt install -y vulkan-tools mesa-vulkan-drivers
```

**Fedora:**
```bash
sudo dnf install -y vulkan-tools mesa-vulkan-drivers
```

**Arch Linux:**
```bash
sudo pacman -S --noconfirm vulkan-tools vulkan-icd-loader
```

### 32-bit Support Not Enabled (Ubuntu/Debian)

```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y lib32gcc-s1 lib32stdc++6
```

### Proton Not Found

1. Open Steam
2. Go to **Settings** → **Compatibility**
3. Enable **"Enable Steam Play for supported titles"**
4. Optionally enable **"Enable Steam Play for all other titles"**
5. Select your preferred Proton version
6. Restart Steam

## Enabling Proton in Steam

Proton allows you to run Windows games on Linux. To enable it:

1. **Launch Steam**
2. Click **Steam** → **Settings**
3. Navigate to **Compatibility** tab
4. Check **"Enable Steam Play for supported titles"**
5. Optionally check **"Enable Steam Play for all other titles"** for experimental support
6. Select your Proton version from the dropdown
7. Click **OK** and restart Steam

## Game Compatibility

Check game compatibility at [ProtonDB](https://www.protondb.com/) - a community database rating how well games run with Proton.

Ratings:
- **Platinum**: Runs perfectly out of the box
- **Gold**: Runs perfectly after tweaks
- **Silver**: Runs with minor issues
- **Bronze**: Runs but has significant issues
- **Borked**: Doesn't run

## Graphics Driver Recommendations

### NVIDIA
```bash
# Ubuntu/Debian
sudo apt install -y nvidia-driver-XXX  # Replace XXX with version

# Fedora
sudo dnf install -y akmod-nvidia

# Arch
sudo pacman -S --noconfirm nvidia nvidia-utils
```

### AMD
```bash
# Ubuntu/Debian (usually pre-installed)
sudo apt install -y mesa-vulkan-drivers libvulkan1

# Fedora
sudo dnf install -y mesa-vulkan-drivers vulkan-loader

# Arch
sudo pacman -S --noconfirm mesa vulkan-radeon
```

### Intel
```bash
# Ubuntu/Debian
sudo apt install -y mesa-vulkan-drivers intel-media-va-driver

# Fedora
sudo dnf install -y mesa-vulkan-drivers intel-media-driver

# Arch
sudo pacman -S --noconfirm mesa vulkan-intel
```

## Advanced Usage

### Environment Variables

Some games require specific environment variables. Common ones:

```bash
# Force Proton version
PROTON_VERSION=proton-7.0

# Enable logging
PROTON_LOG=1

# Use custom Proton
STEAM_COMPAT_DATA_PATH=~/.proton
```

### Performance Tweaks

1. **GameMode**: Install gamemode for automatic performance optimization
```bash
# Ubuntu/Debian
sudo apt install -y gamemode

# Fedora
sudo dnf install -y gamemode

# Arch
sudo pacman -S --noconfirm gamemode
```

2. **MangoHud**: FPS and performance overlay
```bash
# Ubuntu/Debian
sudo apt install -y mangohud

# Fedora
sudo dnf install -y mangohud

# Arch
sudo pacman -S --noconfirm mangohud
```

## Troubleshooting

### Application won't run
1. Ensure Python 3 is installed: `python3 --version`
2. Check file permissions: `chmod +x steam_proton_helper.py`
3. Run with Python directly: `python3 steam_proton_helper.py`

### False negatives
- The tool makes best-effort checks
- Some dependencies might be installed but not detected
- Manual verification is always recommended

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source and available under the MIT License.

## Resources

- [Steam for Linux](https://store.steampowered.com/linux)
- [Proton GitHub](https://github.com/ValveSoftware/Proton)
- [ProtonDB](https://www.protondb.com/)
- [Linux Gaming Wiki](https://linux-gaming.kwindu.eu/)
- [r/linux_gaming](https://www.reddit.com/r/linux_gaming/)

## Disclaimer

This tool is provided as-is for informational purposes. Always verify system changes before executing suggested commands. The authors are not responsible for any system modifications.
