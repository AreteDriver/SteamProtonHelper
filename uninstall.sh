#!/bin/bash
# Uninstallation script for Steam Proton Helper

echo "╔══════════════════════════════════════════╗"
echo "║  Steam Proton Helper - Uninstall         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Remove system-wide command
if [ -L /usr/local/bin/steam-proton-helper ]; then
    read -p "Remove system-wide command? (requires sudo) [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -f /usr/local/bin/steam-proton-helper
        echo "✓ Removed /usr/local/bin/steam-proton-helper"
    fi
fi

# Remove desktop integration
if [ -f ~/.local/share/applications/steam-proton-helper.desktop ]; then
    read -p "Remove desktop menu entry and icons? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f ~/.local/share/applications/steam-proton-helper.desktop
        rm -f ~/.local/share/icons/hicolor/256x256/apps/steam-proton-helper.png
        rm -f ~/.local/share/icons/hicolor/128x128/apps/steam-proton-helper.png
        rm -f ~/.local/share/icons/hicolor/64x64/apps/steam-proton-helper.png
        rm -f ~/.local/share/icons/hicolor/48x48/apps/steam-proton-helper.png
        rm -f ~/.local/share/icons/hicolor/scalable/apps/steam-proton-helper.svg
        echo "✓ Removed desktop entry and icons"

        # Update icon cache
        if command -v update-desktop-database &> /dev/null; then
            update-desktop-database ~/.local/share/applications 2>/dev/null || true
        fi
        if command -v gtk-update-icon-cache &> /dev/null; then
            gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor 2>/dev/null || true
        fi
    fi
fi

# Remove shell completions
COMPLETIONS_EXIST=false
[ -f ~/.local/share/bash-completion/completions/steam-proton-helper ] && COMPLETIONS_EXIST=true
[ -f ~/.zsh/completions/_steam-proton-helper ] && COMPLETIONS_EXIST=true
[ -f ~/.config/fish/completions/steam-proton-helper.fish ] && COMPLETIONS_EXIST=true

if [ "$COMPLETIONS_EXIST" = true ]; then
    read -p "Remove shell completions? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f ~/.local/share/bash-completion/completions/steam-proton-helper
        rm -f ~/.zsh/completions/_steam-proton-helper
        rm -f ~/.config/fish/completions/steam-proton-helper.fish
        echo "✓ Removed shell completions"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Uninstall Complete!                     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "The source directory has not been removed."
echo "Delete it manually if no longer needed."
echo ""
