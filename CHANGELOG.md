# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI/CD workflow for automated testing
- Support for Python 3.6 through 3.12
- Comprehensive test suite with 14 unit tests
- Security scanning in CI pipeline

### Changed
- N/A

### Fixed
- N/A

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

[Unreleased]: https://github.com/AreteDriver/SteamProtonHelper/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AreteDriver/SteamProtonHelper/releases/tag/v1.0.0
