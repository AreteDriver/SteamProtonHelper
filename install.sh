#!/bin/bash
# Installation script for Steam Proton Helper

echo "╔══════════════════════════════════════════╗"
echo "║  Steam Proton Helper - Quick Install    ║"
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
chmod +x steam_proton_helper.py
echo "✓ Made steam_proton_helper.py executable"

# Create a symlink in /usr/local/bin (optional, requires sudo)
read -p "Do you want to install steam-proton-helper system-wide? (requires sudo) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo ln -sf "$(pwd)/steam_proton_helper.py" /usr/local/bin/steam-proton-helper
    echo "✓ Created system-wide command 'steam-proton-helper'"
    echo "  You can now run 'steam-proton-helper' from anywhere"
else
    echo "⊙ Skipped system-wide installation"
    echo "  You can run './steam_proton_helper.py' from this directory"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Installation Complete!                  ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Run the helper with:"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "  steam-proton-helper"
else
    echo "  ./steam_proton_helper.py"
fi
echo ""
