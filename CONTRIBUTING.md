# Contributing to Steam Proton Helper

Thank you for your interest in contributing to Steam Proton Helper! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:

1. Check if the issue already exists in the [GitHub Issues](https://github.com/AreteDriver/SteamProtonHelper/issues)
2. If not, create a new issue with:
   - Clear description of the problem or suggestion
   - Steps to reproduce (for bugs)
   - Your Linux distribution and version
   - Python version
   - Any relevant error messages

### Submitting Changes

1. **Fork the repository**
   ```bash
   git clone https://github.com/AreteDriver/SteamProtonHelper.git
   cd SteamProtonHelper
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test your changes**
   ```bash
   python3 test_steam_proton_helper.py
   python3 steam_proton_helper.py
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

6. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- Follow PEP 8 guidelines for Python code
- Use type hints where appropriate
- Add docstrings to classes and functions
- Keep functions focused and single-purpose
- Use meaningful variable and function names

## Testing

- Write tests for new functionality
- Ensure all existing tests pass
- Test on multiple distributions if possible

## Areas for Contribution

### High Priority
- Support for additional Linux distributions
- More comprehensive package detection
- Better error handling and user feedback
- Performance improvements

### Medium Priority
- Automated fixes for common issues
- Integration with package managers for auto-installation
- Configuration file support
- Logging functionality

### Nice to Have
- GUI version
- Web-based dashboard
- Docker/container support
- Game-specific optimizations

## Development Setup

1. **Clone and install**
   ```bash
   git clone https://github.com/AreteDriver/SteamProtonHelper.git
   cd SteamProtonHelper
   python3 -m pip install --user -e .
   ```

2. **Run in development mode**
   ```bash
   python3 steam_proton_helper.py
   ```

3. **Run tests**
   ```bash
   python3 test_steam_proton_helper.py
   ```

## Adding Support for New Distributions

To add support for a new Linux distribution:

1. Update `DistroDetector.detect_distro()` to recognize the new distro
2. Add package manager mapping
3. Update package names in `DependencyChecker` methods
4. Test on the actual distribution
5. Update documentation

Example:
```python
# In DistroDetector.detect_distro()
elif distro_id in ['newdistro', 'variant']:
    return (distro_id, 'new-package-manager')

# In DependencyChecker methods
required_libs = {
    'apt': [...],
    'dnf': [...],
    'new-package-manager': ['package1', 'package2'],
}
```

## Adding New Checks

To add a new dependency check:

1. Create a method in `DependencyChecker` class
2. Return a `DependencyCheck` or list of `DependencyCheck` objects
3. Call the method in `run_all_checks()`
4. Add tests for the new check
5. Update documentation

Example:
```python
def check_new_dependency(self) -> DependencyCheck:
    """Check for new dependency"""
    if self.check_command_exists('new-command'):
        return DependencyCheck(
            name="New Dependency",
            status=CheckStatus.PASS,
            message="New dependency is installed"
        )
    else:
        return DependencyCheck(
            name="New Dependency",
            status=CheckStatus.FAIL,
            message="New dependency not found",
            fix_command=self._get_install_command('new-package')
        )
```

## Documentation

When adding features:
- Update README.md with usage examples
- Add entries to troubleshooting section
- Update the feature list
- Add code comments for complex logic

## Questions?

Feel free to:
- Open an issue for questions
- Join discussions in existing issues
- Reach out to maintainers

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the Golden Rule

Thank you for contributing! 🎮
