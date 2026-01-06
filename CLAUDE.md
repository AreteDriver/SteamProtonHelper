# Steam Proton Helper - Project Instructions

## Project Overview
Comprehensive Linux tool for Steam and Proton gaming setup. System checks, GE-Proton management, ProtonDB lookups, and a PyQt6 GUI.

**Stack**: Python, PyQt6 (GUI), requests
**Version**: 2.2.x
**Platform**: Linux only

---

## Architecture

```
├── steam_proton_helper.py    # Core CLI module
├── steam_proton_helper_gui.py # GUI entry point
├── gui/                       # PyQt6 GUI components
│   ├── main_window.py
│   ├── system_checks_tab.py
│   ├── proton_tab.py
│   └── protondb_tab.py
├── completions/               # Shell completions (bash, zsh, fish)
└── resources/                 # Icons, assets
```

### Key Features
- **System Checks**: Vulkan, drivers, dependencies, permissions
- **Proton Management**: Install/update GE-Proton releases
- **ProtonDB Lookup**: Game compatibility ratings
- **Auto-fix**: Attempt to resolve common issues

---

## Development Workflow

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run CLI
steam-proton-helper --help

# Run GUI
steam-proton-helper-gui

# Test
pytest

# Lint
ruff check .
ruff format .
```

---

## CLI Commands

```bash
# Full system check
steam-proton-helper check

# Install GE-Proton
steam-proton-helper proton install

# Lookup game on ProtonDB
steam-proton-helper protondb "Game Name"

# Apply fixes
steam-proton-helper fix --all
```

---

## Code Conventions
- CLI uses argparse with subcommands
- GUI uses PyQt6 signal/slot architecture
- System checks return structured results (pass/fail/warning)
- Type hints required
- ruff for linting/formatting

---

## Distribution

```bash
# Build wheel
python -m build

# Install from PyPI
pip install steam-proton-helper

# Install with GUI
pip install steam-proton-helper[gui]
```

---

## Key APIs
- **GE-Proton**: GitHub Releases API (GloriousEggroll/proton-ge-custom)
- **ProtonDB**: protondb.com API for compatibility ratings
- **Steam**: Local file parsing (~/.steam/, compatdata)
