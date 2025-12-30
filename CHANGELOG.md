# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.9.0] - 2025-12-29

### Added
- **--check-updates flag** - Check if newer GE-Proton versions are available
- **--update-proton flag** - Update to the latest GE-Proton version
- Compares installed GE-Proton against latest GitHub release
- JSON output support for update status
- Works with --force to reinstall even if up to date
- 4 new unit tests (150 total)

## [1.8.0] - 2025-12-29

### Added
- **--remove-proton flag** - Uninstall custom Proton versions
- `--remove-proton list` shows removable custom Proton versions
- `--remove-proton GE-Proton9-7` removes a specific version
- Only custom Proton (compatibilitytools.d) can be removed, not official Steam Proton
- Confirmation prompt before deletion (skip with `-y`)
- JSON output support for version listing
- 4 new unit tests (146 total)

## [1.7.1] - 2025-12-29

### Changed
- Updated shell completions (Bash, Zsh, Fish) with new flags:
  - `--search` - Search Steam for games
  - `--list-proton` - List installed Proton versions
  - `--install-proton` - Install GE-Proton (with `list`/`latest` suggestions)
  - `--force` - Force reinstall

## [1.7.0] - 2025-12-29

### Added
- **--install-proton flag** - Download and install GE-Proton versions
- `--install-proton list` shows available versions with install status
- `--install-proton latest` installs the newest GE-Proton
- `--install-proton GE-Proton10-26` installs specific version
- `--force` flag to reinstall existing versions
- Progress indicator during download
- Automatic extraction to Steam's compatibilitytools.d
- JSON output support for version listing
- 4 new unit tests (142 total)

## [1.6.0] - 2025-12-29

### Added
- **--list-proton flag** - List all detected Proton installations
- Separates official Steam Proton from custom builds (GE-Proton, etc.)
- JSON output support with `--list-proton --json`
- Verbose mode shows full installation paths
- 3 new unit tests (138 total)

## [1.5.0] - 2025-12-29

### Added
- **Game name search** - `--game` now accepts game names, not just AppIDs
- **Batch check** - Check multiple games with `--game A --game B` or `--game "A,B"`
- **--search flag** - Search Steam for games without ProtonDB lookup
- Steam Store API integration for game name resolution
- Shows multiple matches when search is ambiguous
- JSON output for batch and search queries
- 16 new unit tests (135 total)

## [1.4.0] - 2025-12-27

### Added
- **ProtonDB integration** - Check game compatibility with `--game APPID`
- Fetch tier rating (platinum/gold/silver/bronze/borked)
- Display confidence score, total reports, and trending tier
- JSON output support for ProtonDB queries
- 7 new unit tests for ProtonDB functionality (119 total)

## [1.3.0] - 2025-12-27

### Added
- **--version / -V flag** - Display version from CLI
- **Shell completions** - Tab completion for Bash, Zsh, and Fish
- **Steam Runtime check** - Detects soldier/sniper/legacy container runtime
- **Pressure Vessel check** - Container isolation tool detection
- **vkBasalt check** - Post-processing layer (CAS, FXAA, SMAA)
- **libstrangle check** - FPS limiter for power/heat reduction
- **OBS Game Capture check** - Vulkan/OpenGL capture for streaming
- 12 new unit tests (112 total)
- Shell completion installation in install.sh/uninstall.sh
- completions/ directory with Bash, Zsh, Fish scripts

### Changed
- New check categories: Runtime, Enhancements
- Expanded to 23 total checks across 10 categories
- Updated MANIFEST.in to include completions

## [1.2.0] - 2025-12-27

### Added
- **GameMode check** - Detects GameMode daemon for CPU/IO optimization
- **MangoHud check** - Detects MangoHud performance overlay
- **Wine check** - Detects standalone Wine installation and version
- **Winetricks check** - Detects Winetricks helper tool
- **DXVK check** - Detects standalone DXVK or Proton's bundled version
- **VKD3D-Proton check** - Detects DirectX 12 to Vulkan translation layer
- 12 new unit tests for gaming tools, Wine, and compatibility checks (100 total)

### Changed
- Expanded check categories: Gaming Tools, Wine, Compatibility
- Improved help text with Steam launch option examples

## [1.1.0] - 2025-12-27

### Added
- `--fix` option to generate shell scripts with fix commands
- `--apply` option to auto-install missing packages with confirmation
- `--dry-run` option to preview what would be installed
- `--yes` / `-y` flag to skip confirmation prompts
- `--verbose` / `-v` flag to show debug output
- `--no-color` flag to disable ANSI colors
- `--json` flag for machine-readable output
- VDF parser for Steam library folder detection
- Multi-library support for Steam installations
- Desktop integration with install.sh (icon and menu entry)
- Uninstall script (uninstall.sh)
- Application icon (SVG and PNG formats)
- `__version__` module attribute
- Comprehensive test suite with 88 unit tests
- pytest configuration in pyproject.toml
- GitHub Actions CI/CD workflow for automated testing
- Security scanning in CI pipeline

### Changed
- Complete code refactor with improved architecture
- Improved Steam detection (Native, Flatpak, Snap)
- Enhanced Proton detection across all Steam libraries
- Better 32-bit/multilib package detection per distro
- Updated pyproject.toml to use SPDX license format

### Fixed
- Steam root directory detection for various installation types
- VDF parsing for unusual file formats

## [1.0.0] - 2025-12-08

### Added
- Initial release of Steam Proton Helper
- Linux distribution detection (Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE)
- Steam client installation check
- Proton compatibility layer verification
- Graphics driver checks (Vulkan, Mesa/OpenGL)
- 32-bit library support verification
- Wine dependencies check
- Color-coded terminal output
- Installation script (install.sh)
- Comprehensive README with usage examples
- Contributing guidelines
- MIT License

### Features
- Automatic dependency detection
- Smart troubleshooting with fix commands
- Support for multiple package managers (apt, dnf, pacman, zypper)
- No external dependencies (Python standard library only)

[Unreleased]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.9.0...HEAD
[1.9.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.7.1...v1.8.0
[1.7.1]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AreteDriver/SteamProtonHelper/releases/tag/v1.0.0
