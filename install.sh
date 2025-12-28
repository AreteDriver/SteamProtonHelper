#!/bin/bash
# Installation script for Steam Proton Helper

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════╗"
echo "║  Steam Proton Helper - Quick Install     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.6 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✓ Found Python $PYTHON_VERSION"

# Make the script executable
chmod +x "$SCRIPT_DIR/steam_proton_helper.py"
echo "✓ Made steam_proton_helper.py executable"

# Create a symlink in /usr/local/bin (optional, requires sudo)
read -p "Install system-wide command? (requires sudo) [y/N] " -n 1 -r
echo
INSTALL_SYSTEM=false
if [[ $REPLY =~ ^[Yy]$ ]]; then
    INSTALL_SYSTEM=true
    sudo ln -sf "$SCRIPT_DIR/steam_proton_helper.py" /usr/local/bin/steam-proton-helper
    echo "✓ Created system-wide command 'steam-proton-helper'"
else
    echo "⊙ Skipped system-wide installation"
fi

# Install desktop integration
read -p "Install desktop menu entry and icon? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Create directories
    mkdir -p ~/.local/share/applications
    mkdir -p ~/.local/share/icons/hicolor/256x256/apps
    mkdir -p ~/.local/share/icons/hicolor/128x128/apps
    mkdir -p ~/.local/share/icons/hicolor/64x64/apps
    mkdir -p ~/.local/share/icons/hicolor/48x48/apps
    mkdir -p ~/.local/share/icons/hicolor/scalable/apps

    # Copy icons
    if [ -f "$SCRIPT_DIR/assets/icon-256.png" ]; then
        cp "$SCRIPT_DIR/assets/icon-256.png" ~/.local/share/icons/hicolor/256x256/apps/steam-proton-helper.png
        cp "$SCRIPT_DIR/assets/icon-128.png" ~/.local/share/icons/hicolor/128x128/apps/steam-proton-helper.png
        cp "$SCRIPT_DIR/assets/icon-64.png" ~/.local/share/icons/hicolor/64x64/apps/steam-proton-helper.png
        cp "$SCRIPT_DIR/assets/icon-48.png" ~/.local/share/icons/hicolor/48x48/apps/steam-proton-helper.png
        echo "✓ Installed PNG icons"
    fi

    if [ -f "$SCRIPT_DIR/assets/icon.svg" ]; then
        cp "$SCRIPT_DIR/assets/icon.svg" ~/.local/share/icons/hicolor/scalable/apps/steam-proton-helper.svg
        echo "✓ Installed SVG icon"
    fi

    # Create desktop file with correct Exec path
    if [ "$INSTALL_SYSTEM" = true ]; then
        EXEC_PATH="steam-proton-helper"
    else
        EXEC_PATH="$SCRIPT_DIR/steam_proton_helper.py"
    fi

    cat > ~/.local/share/applications/steam-proton-helper.desktop << EOF
[Desktop Entry]
Name=Steam Proton Helper
GenericName=Gaming Dependency Checker
Comment=Check system readiness for Steam and Proton gaming on Linux
Exec=$EXEC_PATH
Icon=steam-proton-helper
Terminal=true
Type=Application
Categories=Game;Utility;System;
Keywords=steam;proton;gaming;linux;wine;vulkan;checker;
StartupNotify=false
EOF

    echo "✓ Installed desktop menu entry"

    # Update icon cache
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database ~/.local/share/applications 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache &> /dev/null; then
        gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor 2>/dev/null || true
    fi

    echo "✓ Updated desktop database"
else
    echo "⊙ Skipped desktop integration"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Installation Complete!                  ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Run the helper with:"
if [ "$INSTALL_SYSTEM" = true ]; then
    echo "  steam-proton-helper"
    echo "  steam-proton-helper --json"
    echo "  steam-proton-helper --verbose"
else
    echo "  $SCRIPT_DIR/steam_proton_helper.py"
fi
echo ""
