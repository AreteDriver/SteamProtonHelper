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

[Unreleased]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AreteDriver/SteamProtonHelper/releases/tag/v1.0.0
