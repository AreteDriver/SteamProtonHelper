# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- N/A

### Changed
- N/A

### Fixed
- N/A

## [1.4.0] - 2025-12-27

### Added
- **ProtonDB integration** - Check game compatibility with `--game APPID`
- Fetch tier rating (platinum/gold/silver/bronze/borked)
- Display confidence score, total reports, and trending tier
- JSON output support for ProtonDB queries
- 7 new unit tests for ProtonDB functionality (119 total)

## [1.3.0] - 2025-12-28

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

## [1.2.0] - 2025-12-28

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

[Unreleased]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AreteDriver/SteamProtonHelper/releases/tag/v1.0.0
