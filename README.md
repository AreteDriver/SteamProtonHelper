# Steam Proton Helper 🎮

A comprehensive Linux tool to help setup Steam and Proton for gaming. This application checks dependencies, verifies installations, and helps troubleshoot common issues to get you gaming faster!

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

#### Option 1: Install via pip (Recommended)
```bash
pip install git+https://github.com/AreteDriver/SteamProtonHelper.git
steam-proton-helper
```

#### Option 2: Clone and run directly
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

#### Option 3: Use the installation script
```bash
git clone https://github.com/AreteDriver/SteamProtonHelper.git
cd SteamProtonHelper
./install.sh
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
