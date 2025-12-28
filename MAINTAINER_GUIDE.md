# Maintainer Guide

This guide is for project maintainers and contributors who need to perform common maintenance tasks.

## Quick Reference

### Running Tests
```bash
# Run all tests
python3 test_steam_proton_helper.py

# Run tests with verbose output
python3 test_steam_proton_helper.py -v
```

### Validating Code
```bash
# Check Python syntax
python3 -m py_compile steam_proton_helper.py test_steam_proton_helper.py

# Validate setup.py
python3 setup.py check

# Test the application
python3 steam_proton_helper.py
```

### Creating a Release

1. **Update version numbers:**
   - `setup.py` - Update version
   - `pyproject.toml` - Update version
   - `CHANGELOG.md` - Add release notes

2. **Tag the release:**
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

3. **Create GitHub Release:**
   - Go to GitHub Releases
   - Click "Draft a new release"
   - Select the tag
   - Add release notes from CHANGELOG.md
   - Publish release

4. **Publish to PyPI (optional):**
   ```bash
   python3 -m pip install --upgrade build twine
   python3 -m build
   python3 -m twine upload dist/*
   ```

### Testing Installation

**Test pip installation from local source:**
```bash
pip install -e .
steam-proton-helper
```

**Test pip installation from git:**
```bash
pip install git+https://github.com/AreteDriver/SteamProtonHelper.git
```

**Test installation script:**
```bash
./install.sh
```

### CI/CD

**GitHub Actions Workflow:**
- Located at: `.github/workflows/ci.yml`
- Triggered on: Push to main/develop, Pull Requests
- Runs: Tests, Linting, Security scans

**Manual workflow trigger:**
- Go to Actions tab in GitHub
- Select workflow
- Click "Run workflow"

### Code Quality

**Linting (if tools installed):**
```bash
# Install linting tools
pip install flake8 pylint

# Run flake8
flake8 steam_proton_helper.py test_steam_proton_helper.py

# Run pylint
pylint steam_proton_helper.py test_steam_proton_helper.py
```

**Security scanning (if tools installed):**
```bash
# Install security tools
pip install bandit

# Run bandit
bandit -r steam_proton_helper.py
```

### Common Tasks

**Add a new dependency check:**
1. Add method to `DependencyChecker` class
2. Return `DependencyCheck` object(s)
3. Call method in `run_all_checks()`
4. Add tests in `test_steam_proton_helper.py`
5. Update documentation

**Add support for new distribution:**
1. Update `DistroDetector.detect_distro()`
2. Add package manager mapping
3. Update package names in `DependencyChecker`
4. Test on actual distribution
5. Update README.md

**Update documentation:**
1. Modify relevant .md files
2. Keep examples current
3. Update CHANGELOG.md
4. Ensure consistency across all docs

### Troubleshooting

**Tests failing:**
1. Check Python version compatibility
2. Verify no external dependencies introduced
3. Review test output for specific failures
4. Check if system-specific issues

**Installation issues:**
1. Verify setup.py and pyproject.toml are in sync
2. Check MANIFEST.in includes all needed files
3. Test in clean virtual environment

**CI failing:**
1. Check GitHub Actions workflow syntax
2. Review failed job logs
3. Test locally with same Python version
4. Check for platform-specific issues

### Version Compatibility

**Supported Python Versions:**
- Python 3.6
- Python 3.7
- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11
- Python 3.12

**Supported Distributions:**
- Ubuntu/Debian (apt)
- Fedora/RHEL/CentOS (dnf)
- Arch/Manjaro (pacman)
- openSUSE (zypper)

### Best Practices

1. **Always run tests** before committing
2. **Update CHANGELOG.md** for all changes
3. **Keep documentation** in sync with code
4. **Follow PEP 8** style guidelines
5. **Add tests** for new features
6. **Review security** implications
7. **Test on multiple** Python versions

### Getting Help

- Review CONTRIBUTING.md
- Check existing GitHub issues
- Read project documentation
- Contact project maintainers

---

**Remember:** This project has zero external dependencies and should remain that way for maximum compatibility and ease of use.
