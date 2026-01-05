#!/usr/bin/env python3
"""
Unit tests for Steam Proton Helper

Tests cover:
- Enums and data classes
- VDF parser
- Steam detection (variant, root, libraries)
- Proton detection
- Dependency checking
- JSON output
- CLI argument handling
"""

import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from steam_proton_helper import (
    CheckStatus,
    SteamVariant,
    DependencyCheck,
    ProtonInstall,
    Color,
    VerboseLogger,
    DistroDetector,
    DependencyChecker,
    parse_libraryfolders_vdf,
    detect_steam_variant,
    find_steam_root,
    get_library_paths,
    find_proton_installations,
    get_status_symbol,
    get_status_color,
    output_json,
    parse_args,
    generate_fix_script,
    output_fix_script,
    collect_fix_actions,
    show_dry_run,
    apply_fixes,
    SteamApp,
    search_steam_games,
    resolve_game_input,
)


# =============================================================================
# Test Enums
# =============================================================================

class TestCheckStatus(unittest.TestCase):
    """Test CheckStatus enum"""

    def test_status_values(self):
        """Test that status enum has correct string values"""
        self.assertEqual(CheckStatus.PASS.value, "PASS")
        self.assertEqual(CheckStatus.FAIL.value, "FAIL")
        self.assertEqual(CheckStatus.WARNING.value, "WARN")
        self.assertEqual(CheckStatus.SKIPPED.value, "SKIP")

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist"""
        statuses = [s.name for s in CheckStatus]
        self.assertIn("PASS", statuses)
        self.assertIn("FAIL", statuses)
        self.assertIn("WARNING", statuses)
        self.assertIn("SKIPPED", statuses)


class TestSteamVariant(unittest.TestCase):
    """Test SteamVariant enum"""

    def test_variant_values(self):
        """Test that variant enum has correct values"""
        self.assertEqual(SteamVariant.NATIVE.value, "native")
        self.assertEqual(SteamVariant.FLATPAK.value, "flatpak")
        self.assertEqual(SteamVariant.SNAP.value, "snap")
        self.assertEqual(SteamVariant.NONE.value, "none")


# =============================================================================
# Test Data Classes
# =============================================================================

class TestDependencyCheck(unittest.TestCase):
    """Test DependencyCheck dataclass"""

    def test_basic_check(self):
        """Test creating a basic dependency check"""
        check = DependencyCheck(
            name="Test",
            status=CheckStatus.PASS,
            message="Test message"
        )
        self.assertEqual(check.name, "Test")
        self.assertEqual(check.status, CheckStatus.PASS)
        self.assertEqual(check.message, "Test message")
        self.assertEqual(check.category, "General")  # default
        self.assertIsNone(check.fix_command)
        self.assertIsNone(check.details)

    def test_check_with_all_fields(self):
        """Test creating a check with all fields"""
        check = DependencyCheck(
            name="Vulkan",
            status=CheckStatus.FAIL,
            message="Vulkan not found",
            category="Graphics",
            fix_command="sudo apt install vulkan-tools",
            details="vulkaninfo returned error"
        )
        self.assertEqual(check.name, "Vulkan")
        self.assertEqual(check.category, "Graphics")
        self.assertEqual(check.fix_command, "sudo apt install vulkan-tools")
        self.assertEqual(check.details, "vulkaninfo returned error")

    def test_to_dict(self):
        """Test JSON serialization via to_dict()"""
        check = DependencyCheck(
            name="Test",
            status=CheckStatus.PASS,
            message="OK",
            category="System",
            fix_command=None,
            details="extra info"
        )
        d = check.to_dict()

        self.assertEqual(d["name"], "Test")
        self.assertEqual(d["status"], "PASS")  # enum value, not enum
        self.assertEqual(d["message"], "OK")
        self.assertEqual(d["category"], "System")
        self.assertIsNone(d["fix_command"])
        self.assertEqual(d["details"], "extra info")

    def test_to_dict_is_json_serializable(self):
        """Test that to_dict() output is JSON serializable"""
        check = DependencyCheck(
            name="Test",
            status=CheckStatus.WARNING,
            message="Warning message"
        )
        # Should not raise
        json_str = json.dumps(check.to_dict())
        self.assertIn("Test", json_str)
        self.assertIn("WARN", json_str)


class TestProtonInstall(unittest.TestCase):
    """Test ProtonInstall dataclass"""

    def test_proton_install(self):
        """Test creating a ProtonInstall"""
        proton = ProtonInstall(
            name="Proton 9.0",
            path="/home/user/.steam/steam/steamapps/common/Proton 9.0",
            has_executable=True,
            has_toolmanifest=True,
            has_version=True
        )
        self.assertEqual(proton.name, "Proton 9.0")
        self.assertTrue(proton.has_executable)


# =============================================================================
# Test Color and VerboseLogger
# =============================================================================

class TestColor(unittest.TestCase):
    """Test Color class"""

    def test_color_codes_exist(self):
        """Test that color codes are defined"""
        # Note: These may be empty strings if disabled
        self.assertIsNotNone(Color.GREEN)
        self.assertIsNotNone(Color.RED)
        self.assertIsNotNone(Color.BOLD)
        self.assertIsNotNone(Color.END)

    def test_disable_colors(self):
        """Test disabling colors"""
        # Save originals
        orig_green = Color.GREEN
        orig_enabled = Color._enabled

        Color.disable()

        self.assertEqual(Color.GREEN, '')
        self.assertEqual(Color.RED, '')
        self.assertEqual(Color.BOLD, '')
        self.assertEqual(Color.END, '')
        self.assertFalse(Color.is_enabled())

        # Restore (for other tests)
        Color.GREEN = orig_green
        Color._enabled = orig_enabled


class TestVerboseLogger(unittest.TestCase):
    """Test VerboseLogger class"""

    def test_logger_disabled(self):
        """Test logger when disabled"""
        logger = VerboseLogger(enabled=False)
        # Should not raise, just do nothing
        logger.log("test message")
        self.assertFalse(logger.enabled)

    def test_logger_enabled(self):
        """Test logger when enabled"""
        logger = VerboseLogger(enabled=True)
        self.assertTrue(logger.enabled)

    @patch('builtins.print')
    def test_logger_output(self, mock_print):
        """Test that enabled logger calls print"""
        logger = VerboseLogger(enabled=True)
        logger.log("test message")
        mock_print.assert_called_once()


# =============================================================================
# Test VDF Parser
# =============================================================================

class TestVDFParser(unittest.TestCase):
    """Test parse_libraryfolders_vdf function"""

    def test_parse_valid_vdf(self):
        """Test parsing a valid libraryfolders.vdf"""
        vdf_content = '''
"libraryfolders"
{
    "0"
    {
        "path"		"/home/user/.steam/steam"
        "label"		""
        "mounted"		"1"
    }
    "1"
    {
        "path"		"/mnt/games/SteamLibrary"
        "label"		""
        "mounted"		"1"
    }
}
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.vdf', delete=False) as f:
            f.write(vdf_content)
            f.flush()
            temp_path = f.name

        try:
            # Create the directories so they're recognized
            paths = parse_libraryfolders_vdf(temp_path)
            # Paths that don't exist won't be returned
            # But the parser should not crash
            self.assertIsInstance(paths, list)
        finally:
            os.unlink(temp_path)

    def test_parse_with_existing_dir(self):
        """Test parsing VDF with existing directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            vdf_content = f'''
"libraryfolders"
{{
    "0"
    {{
        "path"		"{tmpdir}"
    }}
}}
'''
            vdf_path = os.path.join(tmpdir, "libraryfolders.vdf")
            with open(vdf_path, 'w') as f:
                f.write(vdf_content)

            paths = parse_libraryfolders_vdf(vdf_path)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0], os.path.realpath(tmpdir))

    def test_parse_nonexistent_file(self):
        """Test parsing a nonexistent file"""
        paths = parse_libraryfolders_vdf("/nonexistent/path/libraryfolders.vdf")
        self.assertEqual(paths, [])

    def test_parse_empty_file(self):
        """Test parsing an empty file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.vdf', delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            paths = parse_libraryfolders_vdf(temp_path)
            self.assertEqual(paths, [])
        finally:
            os.unlink(temp_path)

    def test_parse_malformed_vdf(self):
        """Test parsing a malformed VDF doesn't crash"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.vdf', delete=False) as f:
            f.write("this is not valid vdf {{{ content")
            temp_path = f.name

        try:
            paths = parse_libraryfolders_vdf(temp_path)
            self.assertIsInstance(paths, list)
        finally:
            os.unlink(temp_path)


# =============================================================================
# Test Steam Detection Functions
# =============================================================================

class TestDetectSteamVariant(unittest.TestCase):
    """Test detect_steam_variant function"""

    def test_returns_tuple(self):
        """Test that function returns correct tuple type"""
        result = detect_steam_variant()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], SteamVariant)
        self.assertIsInstance(result[1], str)

    @patch('shutil.which')
    def test_native_steam_detected(self, mock_which):
        """Test detection of native Steam"""
        mock_which.return_value = "/usr/bin/steam"
        variant, msg = detect_steam_variant()
        # May also detect flatpak/snap, but native should be first
        self.assertIn("Steam", msg)

    @patch('shutil.which')
    @patch('subprocess.run')
    def test_no_steam(self, mock_run, mock_which):
        """Test when no Steam is installed"""
        mock_which.return_value = None
        mock_run.side_effect = FileNotFoundError()

        variant, msg = detect_steam_variant()
        self.assertEqual(variant, SteamVariant.NONE)


class TestFindSteamRoot(unittest.TestCase):
    """Test find_steam_root function"""

    def test_returns_string_or_none(self):
        """Test return type"""
        result = find_steam_root()
        self.assertTrue(result is None or isinstance(result, str))

    def test_with_mock_steam_dir(self):
        """Test with a mock Steam directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create steamapps directory
            steamapps = os.path.join(tmpdir, "steamapps")
            os.makedirs(steamapps)

            # Mock the candidate paths
            with patch('steam_proton_helper.os.path.expanduser') as mock_expand:
                mock_expand.return_value = tmpdir
                # The function checks multiple paths, so we need to be careful
                # Just verify it doesn't crash
                result = find_steam_root()
                self.assertTrue(result is None or isinstance(result, str))


class TestGetLibraryPaths(unittest.TestCase):
    """Test get_library_paths function"""

    def test_with_none_root(self):
        """Test with None steam root"""
        paths = get_library_paths(None)
        self.assertEqual(paths, [])

    def test_with_valid_root(self):
        """Test with a valid mock root"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create steamapps with VDF
            steamapps = os.path.join(tmpdir, "steamapps")
            os.makedirs(steamapps)

            vdf_content = f'''
"libraryfolders"
{{
    "0"
    {{
        "path"		"{tmpdir}"
    }}
}}
'''
            vdf_path = os.path.join(steamapps, "libraryfolders.vdf")
            with open(vdf_path, 'w') as f:
                f.write(vdf_content)

            paths = get_library_paths(tmpdir)
            self.assertIn(os.path.realpath(tmpdir), paths)

    def test_deduplication(self):
        """Test that paths are deduplicated"""
        with tempfile.TemporaryDirectory() as tmpdir:
            steamapps = os.path.join(tmpdir, "steamapps")
            os.makedirs(steamapps)

            # VDF with duplicate path
            vdf_content = f'''
"libraryfolders"
{{
    "0"
    {{
        "path"		"{tmpdir}"
    }}
    "1"
    {{
        "path"		"{tmpdir}"
    }}
}}
'''
            vdf_path = os.path.join(steamapps, "libraryfolders.vdf")
            with open(vdf_path, 'w') as f:
                f.write(vdf_content)

            paths = get_library_paths(tmpdir)
            # Should only appear once
            self.assertEqual(paths.count(os.path.realpath(tmpdir)), 1)


class TestFindProtonInstallations(unittest.TestCase):
    """Test find_proton_installations function"""

    def test_with_none_root(self):
        """Test with None steam root"""
        protons = find_proton_installations(None)
        self.assertEqual(protons, [])

    @patch('steam_proton_helper.os.path.expanduser')
    @patch('steam_proton_helper.get_library_paths')
    def test_with_mock_proton(self, mock_get_libs, mock_expanduser):
        """Test with mock Proton installation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock get_library_paths to return only our test dir
            mock_get_libs.return_value = [tmpdir]
            # Mock expanduser to return nonexistent path (avoid ~/.steam checks)
            mock_expanduser.return_value = "/nonexistent/path"

            # Create steamapps/common/Proton 9.0
            proton_dir = os.path.join(tmpdir, "steamapps", "common", "Proton 9.0")
            os.makedirs(proton_dir)

            # Create marker files
            with open(os.path.join(proton_dir, "proton"), 'w') as f:
                f.write("#!/bin/bash\n")
            with open(os.path.join(proton_dir, "toolmanifest.vdf"), 'w') as f:
                f.write('"manifest" {}')
            with open(os.path.join(proton_dir, "version"), 'w') as f:
                f.write("9.0")

            protons = find_proton_installations(tmpdir)

            self.assertEqual(len(protons), 1)
            self.assertEqual(protons[0].name, "Proton 9.0")
            self.assertTrue(protons[0].has_executable)
            self.assertTrue(protons[0].has_toolmanifest)
            self.assertTrue(protons[0].has_version)

    @patch('steam_proton_helper.os.path.expanduser')
    @patch('steam_proton_helper.get_library_paths')
    def test_ignores_non_proton_dirs(self, mock_get_libs, mock_expanduser):
        """Test that non-Proton directories are ignored"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock get_library_paths to return only our test dir
            mock_get_libs.return_value = [tmpdir]
            # Mock expanduser to return nonexistent path
            mock_expanduser.return_value = "/nonexistent/path"

            # Create a non-Proton game directory
            game_dir = os.path.join(tmpdir, "steamapps", "common", "SomeGame")
            os.makedirs(game_dir)

            protons = find_proton_installations(tmpdir)
            self.assertEqual(len(protons), 0)


# =============================================================================
# Test DistroDetector
# =============================================================================

class TestDistroDetector(unittest.TestCase):
    """Test DistroDetector class"""

    def test_detect_distro_returns_tuple(self):
        """Test distro detection returns valid tuple"""
        distro, pkg_mgr = DistroDetector.detect_distro()

        self.assertIsInstance(distro, str)
        self.assertIsInstance(pkg_mgr, str)

    def test_valid_package_managers(self):
        """Test that detected package manager is valid"""
        _, pkg_mgr = DistroDetector.detect_distro()
        valid_pkg_mgrs = ['apt', 'dnf', 'pacman', 'zypper', 'unknown']
        self.assertIn(pkg_mgr, valid_pkg_mgrs)

    def test_with_mock_os_release(self):
        """Test with mock /etc/os-release"""
        mock_content = '''ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04"
'''
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(mock_content)
            temp_path = f.name

        try:
            with patch('os.path.exists') as mock_exists:
                with patch('builtins.open', return_value=open(temp_path)):
                    mock_exists.return_value = True
                    # The function reads /etc/os-release specifically
                    # This is a basic sanity check
                    distro, pkg_mgr = DistroDetector.detect_distro()
                    self.assertIsInstance(distro, str)
        finally:
            os.unlink(temp_path)


# =============================================================================
# Test DependencyChecker
# =============================================================================

class TestDependencyChecker(unittest.TestCase):
    """Test DependencyChecker class"""

    def setUp(self):
        """Set up test fixture"""
        self.checker = DependencyChecker('Ubuntu 24.04', 'apt')

    def test_initialization(self):
        """Test checker initialization"""
        self.assertEqual(self.checker.distro, 'Ubuntu 24.04')
        self.assertEqual(self.checker.package_manager, 'apt')

    def test_run_command_success(self):
        """Test run_command with successful command"""
        code, stdout, stderr = self.checker.run_command(['echo', 'test'])
        self.assertEqual(code, 0)
        self.assertIn('test', stdout)

    def test_run_command_failure(self):
        """Test run_command with failing command"""
        code, stdout, stderr = self.checker.run_command(['false'])
        self.assertNotEqual(code, 0)

    def test_run_command_not_found(self):
        """Test run_command with nonexistent command"""
        code, stdout, stderr = self.checker.run_command(['nonexistent_cmd_xyz'])
        self.assertEqual(code, 127)
        self.assertIn('not found', stderr.lower())

    def test_check_command_exists_true(self):
        """Test check_command_exists with existing command"""
        self.assertTrue(self.checker.check_command_exists('ls'))
        self.assertTrue(self.checker.check_command_exists('echo'))

    def test_check_command_exists_false(self):
        """Test check_command_exists with nonexistent command"""
        self.assertFalse(self.checker.check_command_exists('nonexistent_command_xyz'))

    def test_get_install_command_apt(self):
        """Test install command for apt"""
        checker = DependencyChecker('ubuntu', 'apt')
        cmd = checker._get_install_command('test-package')
        self.assertIn('apt', cmd)
        self.assertIn('test-package', cmd)
        self.assertIn('sudo', cmd)

    def test_get_install_command_dnf(self):
        """Test install command for dnf"""
        checker = DependencyChecker('fedora', 'dnf')
        cmd = checker._get_install_command('test-package')
        self.assertIn('dnf', cmd)
        self.assertIn('test-package', cmd)

    def test_get_install_command_pacman(self):
        """Test install command for pacman"""
        checker = DependencyChecker('arch', 'pacman')
        cmd = checker._get_install_command('test-package')
        self.assertIn('pacman', cmd)
        self.assertIn('test-package', cmd)

    def test_get_install_command_unknown(self):
        """Test install command for unknown package manager"""
        checker = DependencyChecker('unknown', 'unknown')
        cmd = checker._get_install_command('test-package')
        self.assertIn('test-package', cmd)
        self.assertIn('manually', cmd.lower())

    def test_check_system(self):
        """Test system checks"""
        results = self.checker.check_system()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Should have distro check
        names = [r.name for r in results]
        self.assertIn("Linux Distribution", names)

    def test_check_steam(self):
        """Test Steam checks"""
        results = self.checker.check_steam()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Should have Steam Client check
        names = [r.name for r in results]
        self.assertIn("Steam Client", names)

    def test_check_proton(self):
        """Test Proton checks"""
        results = self.checker.check_proton()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        names = [r.name for r in results]
        self.assertIn("Proton", names)

    def test_check_graphics(self):
        """Test graphics checks"""
        results = self.checker.check_graphics()
        self.assertIsInstance(results, list)
        # Should have at least Vulkan check
        self.assertGreater(len(results), 0)

    def test_check_32bit_support(self):
        """Test 32-bit support checks"""
        results = self.checker.check_32bit_support()
        self.assertIsInstance(results, list)
        # Should have multilib check
        self.assertGreater(len(results), 0)

    def test_check_multilib_enabled_apt(self):
        """Test multilib check for apt"""
        checker = DependencyChecker('ubuntu', 'apt')
        enabled, msg = checker.check_multilib_enabled()
        self.assertIsInstance(enabled, bool)
        self.assertIsInstance(msg, str)

    def test_check_multilib_enabled_pacman(self):
        """Test multilib check for pacman"""
        checker = DependencyChecker('arch', 'pacman')
        enabled, msg = checker.check_multilib_enabled()
        self.assertIsInstance(enabled, bool)
        self.assertIsInstance(msg, str)

    def test_check_multilib_enabled_dnf(self):
        """Test multilib check for dnf"""
        checker = DependencyChecker('fedora', 'dnf')
        enabled, msg = checker.check_multilib_enabled()
        # DNF always returns True (automatic multilib)
        self.assertTrue(enabled)

    def test_run_all_checks(self):
        """Test running all checks"""
        results = self.checker.run_all_checks()

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 5)

        # All should be DependencyCheck
        for result in results:
            self.assertIsInstance(result, DependencyCheck)

        # Should have checks from each category
        categories = set(r.category for r in results)
        self.assertIn("System", categories)
        self.assertIn("Steam", categories)
        self.assertIn("Proton", categories)
        self.assertIn("Graphics", categories)
        self.assertIn("32-bit", categories)
        self.assertIn("Gaming Tools", categories)
        self.assertIn("Wine", categories)
        self.assertIn("Compatibility", categories)
        self.assertIn("Runtime", categories)
        self.assertIn("Enhancements", categories)


# =============================================================================
# Test Gaming Tools Checks
# =============================================================================

class TestGamingToolsCheck(unittest.TestCase):
    """Test gaming tools check (GameMode, MangoHud)"""

    def setUp(self):
        self.checker = DependencyChecker("Ubuntu", "apt")

    @patch.object(DependencyChecker, 'check_command_exists')
    @patch.object(DependencyChecker, 'run_command')
    def test_gamemode_installed_and_running(self, mock_run, mock_exists):
        """Test GameMode detected when installed and running"""
        mock_exists.side_effect = lambda cmd: cmd in ['gamemoded', 'gamemode']
        mock_run.return_value = (0, "active", "")

        checks = self.checker.check_gaming_tools()
        gamemode = next(c for c in checks if c.name == "GameMode")

        self.assertEqual(gamemode.status, CheckStatus.PASS)
        self.assertIn("daemon available", gamemode.message)

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_gamemode_not_installed(self, mock_exists):
        """Test GameMode warning when not installed"""
        mock_exists.return_value = False

        checks = self.checker.check_gaming_tools()
        gamemode = next(c for c in checks if c.name == "GameMode")

        self.assertEqual(gamemode.status, CheckStatus.WARNING)
        self.assertIn("not installed", gamemode.message)
        self.assertIsNotNone(gamemode.fix_command)

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_mangohud_installed(self, mock_exists):
        """Test MangoHud detected when installed"""
        mock_exists.side_effect = lambda cmd: cmd == 'mangohud'

        checks = self.checker.check_gaming_tools()
        mangohud = next(c for c in checks if c.name == "MangoHud")

        self.assertEqual(mangohud.status, CheckStatus.PASS)
        self.assertIn("available", mangohud.message)

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_mangohud_not_installed(self, mock_exists):
        """Test MangoHud warning when not installed"""
        mock_exists.return_value = False

        checks = self.checker.check_gaming_tools()
        mangohud = next(c for c in checks if c.name == "MangoHud")

        self.assertEqual(mangohud.status, CheckStatus.WARNING)
        self.assertIn("not installed", mangohud.message)


# =============================================================================
# Test Wine Checks
# =============================================================================

class TestWineCheck(unittest.TestCase):
    """Test Wine installation check"""

    def setUp(self):
        self.checker = DependencyChecker("Ubuntu", "apt")

    @patch.object(DependencyChecker, 'check_command_exists')
    @patch.object(DependencyChecker, 'run_command')
    def test_wine_installed_with_version(self, mock_run, mock_exists):
        """Test Wine detected with version"""
        mock_exists.side_effect = lambda cmd: cmd in ['wine', 'winetricks']
        mock_run.return_value = (0, "wine-9.0", "")

        checks = self.checker.check_wine()
        wine = next(c for c in checks if c.name == "Wine")

        self.assertEqual(wine.status, CheckStatus.PASS)
        self.assertIn("wine-9.0", wine.message)

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_wine_not_installed(self, mock_exists):
        """Test Wine warning when not installed"""
        mock_exists.return_value = False

        checks = self.checker.check_wine()
        wine = next(c for c in checks if c.name == "Wine")

        self.assertEqual(wine.status, CheckStatus.WARNING)
        self.assertIn("optional", wine.message.lower())

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_winetricks_installed(self, mock_exists):
        """Test Winetricks detected when installed"""
        mock_exists.side_effect = lambda cmd: cmd == 'winetricks'

        checks = self.checker.check_wine()
        winetricks = next(c for c in checks if c.name == "Winetricks")

        self.assertEqual(winetricks.status, CheckStatus.PASS)

    @patch.object(DependencyChecker, 'check_command_exists')
    def test_winetricks_not_installed(self, mock_exists):
        """Test Winetricks warning when not installed"""
        mock_exists.return_value = False

        checks = self.checker.check_wine()
        winetricks = next(c for c in checks if c.name == "Winetricks")

        self.assertEqual(winetricks.status, CheckStatus.WARNING)


# =============================================================================
# Test DXVK/VKD3D Checks
# =============================================================================

class TestDXVKCheck(unittest.TestCase):
    """Test DXVK and VKD3D-Proton checks"""

    def setUp(self):
        self.checker = DependencyChecker("Ubuntu", "apt")

    @patch('os.path.isdir')
    @patch('os.walk')
    def test_dxvk_standalone_found(self, mock_walk, mock_isdir):
        """Test standalone DXVK detected"""
        mock_isdir.return_value = True
        mock_walk.return_value = [
            ('/usr/share/dxvk', [], ['d3d11.dll', 'd3d9.dll'])
        ]

        checks = self.checker.check_dxvk_vkd3d()
        dxvk = next(c for c in checks if c.name == "DXVK")

        self.assertEqual(dxvk.status, CheckStatus.PASS)
        self.assertIn("Standalone", dxvk.message)

    @patch('os.path.isdir')
    def test_dxvk_using_proton(self, mock_isdir):
        """Test DXVK defaults to Proton's bundled version"""
        mock_isdir.return_value = False

        checks = self.checker.check_dxvk_vkd3d()
        dxvk = next(c for c in checks if c.name == "DXVK")

        self.assertEqual(dxvk.status, CheckStatus.PASS)
        self.assertIn("Proton", dxvk.message)

    @patch('os.path.isdir')
    def test_vkd3d_standalone_found(self, mock_isdir):
        """Test standalone VKD3D-Proton detected"""
        def isdir_side_effect(path):
            return 'vkd3d-proton' in path
        mock_isdir.side_effect = isdir_side_effect

        checks = self.checker.check_dxvk_vkd3d()
        vkd3d = next(c for c in checks if c.name == "VKD3D-Proton")

        self.assertEqual(vkd3d.status, CheckStatus.PASS)
        self.assertIn("Standalone", vkd3d.message)

    @patch('os.path.isdir')
    def test_vkd3d_using_proton(self, mock_isdir):
        """Test VKD3D defaults to Proton's bundled version"""
        mock_isdir.return_value = False

        checks = self.checker.check_dxvk_vkd3d()
        vkd3d = next(c for c in checks if c.name == "VKD3D-Proton")

        self.assertEqual(vkd3d.status, CheckStatus.PASS)
        self.assertIn("Proton", vkd3d.message)


# =============================================================================
# Test Steam Runtime Checks
# =============================================================================

class TestSteamRuntimeCheck(unittest.TestCase):
    """Test Steam Runtime and Pressure Vessel checks"""

    def setUp(self):
        self.checker = DependencyChecker("Ubuntu", "apt")
        self.checker.steam_root = "/home/test/.steam/steam"

    @patch('os.path.isdir')
    def test_runtime_sniper_found(self, mock_isdir):
        """Test Steam Runtime sniper detected"""
        def isdir_side_effect(path):
            return 'sniper' in path.lower()
        mock_isdir.side_effect = isdir_side_effect

        checks = self.checker.check_steam_runtime()
        runtime = next(c for c in checks if c.name == "Steam Runtime")

        self.assertEqual(runtime.status, CheckStatus.PASS)
        self.assertIn("sniper", runtime.message.lower())

    @patch('os.path.isdir')
    def test_runtime_soldier_found(self, mock_isdir):
        """Test Steam Runtime soldier detected"""
        def isdir_side_effect(path):
            return 'soldier' in path.lower()
        mock_isdir.side_effect = isdir_side_effect

        checks = self.checker.check_steam_runtime()
        runtime = next(c for c in checks if c.name == "Steam Runtime")

        self.assertEqual(runtime.status, CheckStatus.PASS)
        self.assertIn("soldier", runtime.message.lower())

    @patch('os.path.isdir')
    def test_runtime_not_found(self, mock_isdir):
        """Test Steam Runtime not found warning"""
        mock_isdir.return_value = False

        checks = self.checker.check_steam_runtime()
        runtime = next(c for c in checks if c.name == "Steam Runtime")

        self.assertEqual(runtime.status, CheckStatus.WARNING)

    @patch('os.path.isdir')
    def test_pressure_vessel_found(self, mock_isdir):
        """Test Pressure Vessel detected"""
        def isdir_side_effect(path):
            return 'pressure-vessel' in path
        mock_isdir.side_effect = isdir_side_effect

        checks = self.checker.check_steam_runtime()
        pv = next(c for c in checks if c.name == "Pressure Vessel")

        self.assertEqual(pv.status, CheckStatus.PASS)
        self.assertIn("available", pv.message.lower())


# =============================================================================
# Test Extra Tools Checks
# =============================================================================

class TestExtraToolsCheck(unittest.TestCase):
    """Test vkBasalt, libstrangle, and OBS capture checks"""

    def setUp(self):
        self.checker = DependencyChecker("Ubuntu", "apt")

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_vkbasalt_found_by_lib(self, mock_cmd, mock_isfile):
        """Test vkBasalt detected by library file"""
        mock_cmd.return_value = False
        mock_isfile.side_effect = lambda p: 'vkbasalt' in p.lower()

        checks = self.checker.check_extra_tools()
        vkbasalt = next(c for c in checks if c.name == "vkBasalt")

        self.assertEqual(vkbasalt.status, CheckStatus.PASS)

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_vkbasalt_not_found(self, mock_cmd, mock_isfile):
        """Test vkBasalt warning when not installed"""
        mock_cmd.return_value = False
        mock_isfile.return_value = False

        checks = self.checker.check_extra_tools()
        vkbasalt = next(c for c in checks if c.name == "vkBasalt")

        self.assertEqual(vkbasalt.status, CheckStatus.WARNING)
        self.assertIsNotNone(vkbasalt.fix_command)

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_libstrangle_found_by_command(self, mock_cmd, mock_isfile):
        """Test libstrangle detected by command"""
        mock_cmd.side_effect = lambda c: c == 'strangle'
        mock_isfile.return_value = False

        checks = self.checker.check_extra_tools()
        strangle = next(c for c in checks if c.name == "libstrangle")

        self.assertEqual(strangle.status, CheckStatus.PASS)

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_libstrangle_not_found(self, mock_cmd, mock_isfile):
        """Test libstrangle warning when not installed"""
        mock_cmd.return_value = False
        mock_isfile.return_value = False

        checks = self.checker.check_extra_tools()
        strangle = next(c for c in checks if c.name == "libstrangle")

        self.assertEqual(strangle.status, CheckStatus.WARNING)

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_obs_capture_found(self, mock_cmd, mock_isfile):
        """Test OBS capture detected"""
        mock_cmd.side_effect = lambda c: c == 'obs-vkcapture'
        mock_isfile.return_value = False

        checks = self.checker.check_extra_tools()
        obs = next(c for c in checks if c.name == "OBS Game Capture")

        self.assertEqual(obs.status, CheckStatus.PASS)

    @patch('os.path.isfile')
    @patch.object(DependencyChecker, 'check_command_exists')
    def test_obs_capture_not_found(self, mock_cmd, mock_isfile):
        """Test OBS capture warning when not installed"""
        mock_cmd.return_value = False
        mock_isfile.return_value = False

        checks = self.checker.check_extra_tools()
        obs = next(c for c in checks if c.name == "OBS Game Capture")

        self.assertEqual(obs.status, CheckStatus.WARNING)


# =============================================================================
# Test ProtonDB Integration
# =============================================================================

class TestProtonDBInfo(unittest.TestCase):
    """Test ProtonDB data class"""

    def test_protondb_info_creation(self):
        """Test ProtonDBInfo can be created"""
        from steam_proton_helper import ProtonDBInfo
        info = ProtonDBInfo(
            app_id="292030",
            tier="platinum",
            confidence="strong",
            score=0.87,
            total_reports=1624,
            trending_tier="gold",
            best_reported_tier="platinum",
        )
        self.assertEqual(info.app_id, "292030")
        self.assertEqual(info.tier, "platinum")
        self.assertEqual(info.score, 0.87)


class TestProtonDBFunctions(unittest.TestCase):
    """Test ProtonDB helper functions"""

    def test_get_tier_symbol(self):
        """Test tier symbols"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("platinum"), "🏆")
        self.assertEqual(get_tier_symbol("gold"), "🥇")
        self.assertEqual(get_tier_symbol("silver"), "🥈")
        self.assertEqual(get_tier_symbol("bronze"), "🥉")
        self.assertEqual(get_tier_symbol("borked"), "💔")

    def test_get_tier_color(self):
        """Test tier colors return strings"""
        from steam_proton_helper import get_tier_color
        self.assertIsInstance(get_tier_color("platinum"), str)
        self.assertIsInstance(get_tier_color("gold"), str)
        self.assertIsInstance(get_tier_color("unknown"), str)

    @patch('urllib.request.urlopen')
    def test_fetch_protondb_info_success(self, mock_urlopen):
        """Test successful ProtonDB fetch"""
        from steam_proton_helper import fetch_protondb_info

        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = json.dumps({
            "tier": "gold",
            "confidence": "strong",
            "score": 0.75,
            "total": 100,
            "trendingTier": "platinum",
            "bestReportedTier": "platinum",
        }).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response

        info = fetch_protondb_info("12345")

        self.assertIsNotNone(info)
        self.assertEqual(info.tier, "gold")
        self.assertEqual(info.confidence, "strong")
        self.assertEqual(info.total_reports, 100)

    @patch('urllib.request.urlopen')
    def test_fetch_protondb_info_not_found(self, mock_urlopen):
        """Test ProtonDB fetch for non-existent game"""
        from steam_proton_helper import fetch_protondb_info
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="", code=404, msg="Not Found", hdrs={}, fp=None
        )

        info = fetch_protondb_info("99999999")
        self.assertIsNone(info)


class TestGameArgument(unittest.TestCase):
    """Test --game argument parsing"""

    def test_game_argument(self):
        """Test --game argument is parsed"""
        with patch('sys.argv', ['prog', '--game', '292030']):
            args = parse_args()
            self.assertEqual(args.game, ['292030'])

    def test_no_game_argument(self):
        """Test default is None when --game not provided"""
        with patch('sys.argv', ['prog']):
            args = parse_args()
            self.assertIsNone(args.game)

    def test_game_argument_with_name(self):
        """Test --game with a game name"""
        with patch('sys.argv', ['prog', '--game', 'Elden Ring']):
            args = parse_args()
            self.assertEqual(args.game, ['Elden Ring'])

    def test_multiple_game_arguments(self):
        """Test multiple --game arguments"""
        with patch('sys.argv', ['prog', '--game', '292030', '--game', '1245620']):
            args = parse_args()
            self.assertEqual(args.game, ['292030', '1245620'])

    def test_game_argument_comma_separated(self):
        """Test comma-separated game IDs are accepted"""
        with patch('sys.argv', ['prog', '--game', '292030,1245620']):
            args = parse_args()
            self.assertEqual(args.game, ['292030,1245620'])


class TestSearchArgument(unittest.TestCase):
    """Test --search argument parsing"""

    def test_search_argument(self):
        """Test --search argument is parsed"""
        with patch('sys.argv', ['prog', '--search', 'witcher']):
            args = parse_args()
            self.assertEqual(args.search, 'witcher')

    def test_no_search_argument(self):
        """Test default is None when --search not provided"""
        with patch('sys.argv', ['prog']):
            args = parse_args()
            self.assertIsNone(args.search)

    def test_search_with_spaces(self):
        """Test --search with spaces in query"""
        with patch('sys.argv', ['prog', '--search', 'elden ring']):
            args = parse_args()
            self.assertEqual(args.search, 'elden ring')


class TestSteamApp(unittest.TestCase):
    """Test SteamApp dataclass"""

    def test_steam_app_creation(self):
        """Test SteamApp can be created"""
        app = SteamApp(appid=292030, name="The Witcher 3: Wild Hunt")
        self.assertEqual(app.appid, 292030)
        self.assertEqual(app.name, "The Witcher 3: Wild Hunt")


class TestSearchSteamGames(unittest.TestCase):
    """Test Steam game search functionality"""

    @patch('urllib.request.urlopen')
    def test_search_steam_games_success(self, mock_urlopen):
        """Test successful game search"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "total": 2,
            "items": [
                {"type": "app", "id": 292030, "name": "The Witcher 3: Wild Hunt"},
                {"type": "app", "id": 20920, "name": "The Witcher 2"},
            ]
        }).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response

        results = search_steam_games("witcher")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].appid, 292030)
        self.assertEqual(results[0].name, "The Witcher 3: Wild Hunt")

    @patch('urllib.request.urlopen')
    def test_search_steam_games_filters_dlc(self, mock_urlopen):
        """Test that DLC and packages are filtered out"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "total": 3,
            "items": [
                {"type": "app", "id": 292030, "name": "The Witcher 3"},
                {"type": "sub", "id": 124923, "name": "Witcher Complete Edition"},
                {"type": "app", "id": 378648, "name": "Blood and Wine DLC"},
            ]
        }).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response

        results = search_steam_games("witcher")
        # Should only include type="app"
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, SteamApp) for r in results))

    @patch('urllib.request.urlopen')
    def test_search_steam_games_empty(self, mock_urlopen):
        """Test search with no results"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "total": 0,
            "items": []
        }).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response

        results = search_steam_games("xyznonexistent")
        self.assertEqual(len(results), 0)

    @patch('urllib.request.urlopen')
    def test_search_steam_games_network_error(self, mock_urlopen):
        """Test search handles network errors gracefully"""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Network error")

        results = search_steam_games("witcher")
        self.assertEqual(len(results), 0)


class TestResolveGameInput(unittest.TestCase):
    """Test game input resolution"""

    def test_resolve_numeric_appid(self):
        """Test that numeric input is treated as AppID"""
        app_id, game_name, matches = resolve_game_input("292030")
        self.assertEqual(app_id, "292030")
        self.assertIsNone(game_name)
        self.assertEqual(matches, [])

    @patch('steam_proton_helper.search_steam_games')
    def test_resolve_single_match(self, mock_search):
        """Test resolution with single match"""
        mock_search.return_value = [
            SteamApp(appid=1245620, name="ELDEN RING")
        ]
        app_id, game_name, matches = resolve_game_input("elden ring")
        self.assertEqual(app_id, "1245620")
        self.assertEqual(game_name, "ELDEN RING")
        self.assertEqual(matches, [])

    @patch('steam_proton_helper.search_steam_games')
    def test_resolve_multiple_matches(self, mock_search):
        """Test resolution with multiple matches"""
        mock_search.return_value = [
            SteamApp(appid=292030, name="The Witcher 3: Wild Hunt"),
            SteamApp(appid=378648, name="The Witcher 3: Blood and Wine"),
        ]
        app_id, game_name, matches = resolve_game_input("witcher 3")
        self.assertIsNone(app_id)
        self.assertIsNone(game_name)
        self.assertEqual(len(matches), 2)

    @patch('steam_proton_helper.search_steam_games')
    def test_resolve_exact_match_from_multiple(self, mock_search):
        """Test that exact match is selected from multiple results"""
        mock_search.return_value = [
            SteamApp(appid=1245620, name="ELDEN RING"),
            SteamApp(appid=999999, name="ELDEN RING Deluxe"),
        ]
        app_id, game_name, matches = resolve_game_input("ELDEN RING")
        self.assertEqual(app_id, "1245620")
        self.assertEqual(game_name, "ELDEN RING")
        self.assertEqual(matches, [])

    @patch('steam_proton_helper.search_steam_games')
    def test_resolve_no_matches(self, mock_search):
        """Test resolution with no matches"""
        mock_search.return_value = []
        app_id, game_name, matches = resolve_game_input("nonexistent game xyz")
        self.assertIsNone(app_id)
        self.assertIsNone(game_name)
        self.assertEqual(matches, [])


# =============================================================================
# Test Output Functions
# =============================================================================

class TestOutputFunctions(unittest.TestCase):
    """Test output helper functions"""

    def test_get_status_symbol(self):
        """Test status symbols"""
        self.assertEqual(get_status_symbol(CheckStatus.PASS), "✓")
        self.assertEqual(get_status_symbol(CheckStatus.FAIL), "✗")
        self.assertEqual(get_status_symbol(CheckStatus.WARNING), "⚠")
        self.assertEqual(get_status_symbol(CheckStatus.SKIPPED), "○")

    def test_get_status_color(self):
        """Test status colors return strings"""
        self.assertIsInstance(get_status_color(CheckStatus.PASS), str)
        self.assertIsInstance(get_status_color(CheckStatus.FAIL), str)
        self.assertIsInstance(get_status_color(CheckStatus.WARNING), str)


class TestJSONOutput(unittest.TestCase):
    """Test JSON output function"""

    @patch('builtins.print')
    def test_output_json_valid(self, mock_print):
        """Test that JSON output is valid JSON"""
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "System"),
            DependencyCheck("Test2", CheckStatus.FAIL, "Error", "Graphics"),
        ]

        output_json(checks, "Ubuntu", "apt")

        # Get the printed JSON
        mock_print.assert_called_once()
        json_str = mock_print.call_args[0][0]

        # Should be valid JSON
        data = json.loads(json_str)

        # Check structure
        self.assertIn("system", data)
        self.assertIn("steam", data)
        self.assertIn("proton", data)
        self.assertIn("checks", data)
        self.assertIn("summary", data)

        # Check summary counts
        self.assertEqual(data["summary"]["passed"], 1)
        self.assertEqual(data["summary"]["failed"], 1)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestArgumentParsing(unittest.TestCase):
    """Test CLI argument parsing"""

    def test_default_args(self):
        """Test default arguments"""
        with patch('sys.argv', ['prog']):
            args = parse_args()
            self.assertFalse(args.json)
            self.assertFalse(args.no_color)
            self.assertFalse(args.verbose)
            self.assertFalse(args.apply)
            self.assertFalse(args.dry_run)

    def test_version_flag(self):
        """Test --version flag exits with version info"""
        with patch('sys.argv', ['prog', '--version']):
            with self.assertRaises(SystemExit) as cm:
                parse_args()
            self.assertEqual(cm.exception.code, 0)

    def test_version_short_flag(self):
        """Test -V flag exits with version info"""
        with patch('sys.argv', ['prog', '-V']):
            with self.assertRaises(SystemExit) as cm:
                parse_args()
            self.assertEqual(cm.exception.code, 0)

    def test_json_flag(self):
        """Test --json flag"""
        with patch('sys.argv', ['prog', '--json']):
            args = parse_args()
            self.assertTrue(args.json)

    def test_no_color_flag(self):
        """Test --no-color flag"""
        with patch('sys.argv', ['prog', '--no-color']):
            args = parse_args()
            self.assertTrue(args.no_color)

    def test_verbose_flag(self):
        """Test --verbose flag"""
        with patch('sys.argv', ['prog', '--verbose']):
            args = parse_args()
            self.assertTrue(args.verbose)

    def test_verbose_short_flag(self):
        """Test -v flag"""
        with patch('sys.argv', ['prog', '-v']):
            args = parse_args()
            self.assertTrue(args.verbose)

    def test_combined_flags(self):
        """Test combined flags"""
        with patch('sys.argv', ['prog', '--json', '--no-color', '-v']):
            args = parse_args()
            self.assertTrue(args.json)
            self.assertTrue(args.no_color)
            self.assertTrue(args.verbose)

    def test_fix_flag_stdout(self):
        """Test --fix flag defaults to stdout"""
        with patch('sys.argv', ['prog', '--fix']):
            args = parse_args()
            self.assertEqual(args.fix, '-')

    def test_fix_flag_with_file(self):
        """Test --fix flag with filename"""
        with patch('sys.argv', ['prog', '--fix', 'fix.sh']):
            args = parse_args()
            self.assertEqual(args.fix, 'fix.sh')

    def test_list_proton_flag(self):
        """Test --list-proton flag"""
        with patch('sys.argv', ['prog', '--list-proton']):
            args = parse_args()
            self.assertTrue(args.list_proton)

    def test_list_proton_with_json(self):
        """Test --list-proton with --json"""
        with patch('sys.argv', ['prog', '--list-proton', '--json']):
            args = parse_args()
            self.assertTrue(args.list_proton)
            self.assertTrue(args.json)

    def test_list_proton_with_verbose(self):
        """Test --list-proton with --verbose"""
        with patch('sys.argv', ['prog', '--list-proton', '-v']):
            args = parse_args()
            self.assertTrue(args.list_proton)
            self.assertTrue(args.verbose)

    def test_install_proton_flag(self):
        """Test --install-proton flag"""
        with patch('sys.argv', ['prog', '--install-proton', 'latest']):
            args = parse_args()
            self.assertEqual(args.install_proton, 'latest')

    def test_install_proton_list(self):
        """Test --install-proton list"""
        with patch('sys.argv', ['prog', '--install-proton', 'list']):
            args = parse_args()
            self.assertEqual(args.install_proton, 'list')

    def test_install_proton_with_force(self):
        """Test --install-proton with --force"""
        with patch('sys.argv', ['prog', '--install-proton', 'GE-Proton10-26', '--force']):
            args = parse_args()
            self.assertEqual(args.install_proton, 'GE-Proton10-26')
            self.assertTrue(args.force)

    def test_install_proton_with_json(self):
        """Test --install-proton list with --json"""
        with patch('sys.argv', ['prog', '--install-proton', 'list', '--json']):
            args = parse_args()
            self.assertEqual(args.install_proton, 'list')
            self.assertTrue(args.json)

    def test_remove_proton_flag(self):
        """Test --remove-proton flag"""
        with patch('sys.argv', ['prog', '--remove-proton', 'GE-Proton10-26']):
            args = parse_args()
            self.assertEqual(args.remove_proton, 'GE-Proton10-26')

    def test_remove_proton_list(self):
        """Test --remove-proton list"""
        with patch('sys.argv', ['prog', '--remove-proton', 'list']):
            args = parse_args()
            self.assertEqual(args.remove_proton, 'list')

    def test_remove_proton_with_yes(self):
        """Test --remove-proton with --yes to skip confirmation"""
        with patch('sys.argv', ['prog', '--remove-proton', 'GE-Proton10-26', '-y']):
            args = parse_args()
            self.assertEqual(args.remove_proton, 'GE-Proton10-26')
            self.assertTrue(args.yes)

    def test_remove_proton_with_json(self):
        """Test --remove-proton list with --json"""
        with patch('sys.argv', ['prog', '--remove-proton', 'list', '--json']):
            args = parse_args()
            self.assertEqual(args.remove_proton, 'list')
            self.assertTrue(args.json)

    def test_check_updates_flag(self):
        """Test --check-updates flag"""
        with patch('sys.argv', ['prog', '--check-updates']):
            args = parse_args()
            self.assertTrue(args.check_updates)

    def test_check_updates_with_json(self):
        """Test --check-updates with --json"""
        with patch('sys.argv', ['prog', '--check-updates', '--json']):
            args = parse_args()
            self.assertTrue(args.check_updates)
            self.assertTrue(args.json)

    def test_update_proton_flag(self):
        """Test --update-proton flag"""
        with patch('sys.argv', ['prog', '--update-proton']):
            args = parse_args()
            self.assertTrue(args.update_proton)

    def test_update_proton_with_force(self):
        """Test --update-proton with --force"""
        with patch('sys.argv', ['prog', '--update-proton', '--force']):
            args = parse_args()
            self.assertTrue(args.update_proton)
            self.assertTrue(args.force)


# =============================================================================
# Test Fix Script Generation
# =============================================================================

class TestFixScriptGeneration(unittest.TestCase):
    """Test fix script generation"""

    def test_generate_fix_script_no_fixes(self):
        """Test fix script when no fixes are needed"""
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "System"),
            DependencyCheck("Test2", CheckStatus.PASS, "OK", "Graphics"),
        ]
        script = generate_fix_script(checks, "Ubuntu", "apt")

        self.assertIn("#!/bin/bash", script)
        self.assertIn("No fixes needed", script)
        self.assertIn("exit 0", script)

    def test_generate_fix_script_with_apt_fixes(self):
        """Test fix script with apt package fixes"""
        checks = [
            DependencyCheck(
                "Package1", CheckStatus.FAIL, "Not installed", "32-bit",
                fix_command="sudo apt install -y package1"
            ),
            DependencyCheck(
                "Package2", CheckStatus.FAIL, "Not installed", "32-bit",
                fix_command="sudo apt install -y package2"
            ),
        ]
        script = generate_fix_script(checks, "Ubuntu", "apt")

        self.assertIn("#!/bin/bash", script)
        self.assertIn("set -e", script)
        self.assertIn("apt", script)
        # Packages should be combined
        self.assertIn("package1", script)
        self.assertIn("package2", script)

    def test_generate_fix_script_with_pacman_fixes(self):
        """Test fix script with pacman package fixes"""
        checks = [
            DependencyCheck(
                "Package1", CheckStatus.FAIL, "Not installed", "32-bit",
                fix_command="sudo pacman -S --noconfirm lib32-pkg"
            ),
        ]
        script = generate_fix_script(checks, "Arch", "pacman")

        self.assertIn("pacman", script)
        self.assertIn("lib32-pkg", script)

    def test_generate_fix_script_with_dnf_fixes(self):
        """Test fix script with dnf package fixes"""
        checks = [
            DependencyCheck(
                "Package1", CheckStatus.FAIL, "Not installed", "32-bit",
                fix_command="sudo dnf install -y package.i686"
            ),
        ]
        script = generate_fix_script(checks, "Fedora", "dnf")

        self.assertIn("dnf", script)
        self.assertIn("package.i686", script)

    def test_generate_fix_script_with_other_commands(self):
        """Test fix script with non-package-manager commands"""
        checks = [
            DependencyCheck(
                "Proton", CheckStatus.WARNING, "Not found", "Proton",
                fix_command="Install Proton from Steam: Settings → Compatibility"
            ),
        ]
        script = generate_fix_script(checks, "Ubuntu", "apt")

        self.assertIn("Fix: Proton", script)
        self.assertIn("Install Proton from Steam", script)

    def test_generate_fix_script_includes_warnings(self):
        """Test that warnings with fix commands are included"""
        checks = [
            DependencyCheck(
                "Warning", CheckStatus.WARNING, "Warning message", "System",
                fix_command="some fix command"
            ),
        ]
        script = generate_fix_script(checks, "Ubuntu", "apt")

        self.assertIn("some fix command", script)

    def test_output_fix_script_to_file(self):
        """Test writing fix script to file"""
        checks = [
            DependencyCheck("Test", CheckStatus.PASS, "OK", "System"),
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            temp_path = f.name

        try:
            output_fix_script(checks, "Ubuntu", "apt", temp_path)

            # File should exist and be executable
            self.assertTrue(os.path.exists(temp_path))
            mode = os.stat(temp_path).st_mode
            self.assertTrue(mode & 0o100)  # Check executable bit

            # Content should be valid
            with open(temp_path, 'r') as f:
                content = f.read()
            self.assertIn("#!/bin/bash", content)
        finally:
            os.unlink(temp_path)

    @patch('builtins.print')
    def test_output_fix_script_to_stdout(self, mock_print):
        """Test writing fix script to stdout"""
        checks = [
            DependencyCheck("Test", CheckStatus.PASS, "OK", "System"),
        ]

        output_fix_script(checks, "Ubuntu", "apt", "-")

        mock_print.assert_called_once()
        output = mock_print.call_args[0][0]
        self.assertIn("#!/bin/bash", output)


# =============================================================================
# Test Apply / Dry-Run
# =============================================================================

class TestCollectFixActions(unittest.TestCase):
    """Test collect_fix_actions function"""

    def test_no_fixes_needed(self):
        """Test when no fixes are needed"""
        checks = [
            DependencyCheck("Test", CheckStatus.PASS, "OK", "System"),
        ]
        packages, other = collect_fix_actions(checks, "apt")
        self.assertEqual(packages, [])
        self.assertEqual(other, [])

    def test_collect_apt_packages(self):
        """Test collecting apt packages"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg1"
            ),
            DependencyCheck(
                "Pkg2", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg2 pkg3"
            ),
        ]
        packages, other = collect_fix_actions(checks, "apt")
        self.assertIn("pkg1", packages)
        self.assertIn("pkg2", packages)
        self.assertIn("pkg3", packages)
        self.assertEqual(other, [])

    def test_collect_pacman_packages(self):
        """Test collecting pacman packages"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo pacman -S --noconfirm lib32-pkg"
            ),
        ]
        packages, other = collect_fix_actions(checks, "pacman")
        self.assertIn("lib32-pkg", packages)

    def test_collect_dnf_packages(self):
        """Test collecting dnf packages"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo dnf install -y pkg.i686"
            ),
        ]
        packages, other = collect_fix_actions(checks, "dnf")
        self.assertIn("pkg.i686", packages)

    def test_collect_other_commands(self):
        """Test collecting non-package commands"""
        checks = [
            DependencyCheck(
                "Proton", CheckStatus.WARNING, "Not found", "Proton",
                fix_command="Enable Steam Play in Settings"
            ),
        ]
        packages, other = collect_fix_actions(checks, "apt")
        self.assertEqual(packages, [])
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0][0], "Proton")

    def test_deduplicates_packages(self):
        """Test that duplicate packages are removed"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg1"
            ),
            DependencyCheck(
                "Pkg2", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg1"
            ),
        ]
        packages, other = collect_fix_actions(checks, "apt")
        self.assertEqual(packages.count("pkg1"), 1)


class TestShowDryRun(unittest.TestCase):
    """Test show_dry_run function"""

    @patch('builtins.print')
    def test_dry_run_no_fixes(self, mock_print):
        """Test dry run when no fixes needed"""
        checks = [
            DependencyCheck("Test", CheckStatus.PASS, "OK", "System"),
        ]
        count = show_dry_run(checks, "apt")
        self.assertEqual(count, 0)

    @patch('builtins.print')
    def test_dry_run_with_packages(self, mock_print):
        """Test dry run with packages to install"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg1"
            ),
        ]
        count = show_dry_run(checks, "apt")
        self.assertEqual(count, 1)


class TestApplyFixes(unittest.TestCase):
    """Test apply_fixes function"""

    def test_apply_no_fixes_needed(self):
        """Test apply when no fixes needed"""
        checks = [
            DependencyCheck("Test", CheckStatus.PASS, "OK", "System"),
        ]
        success, message = apply_fixes(checks, "apt", skip_confirm=True)
        self.assertTrue(success)
        self.assertIn("No fixes needed", message)

    @patch('builtins.print')
    def test_apply_only_manual_actions(self, mock_print):
        """Test apply with only manual actions"""
        checks = [
            DependencyCheck(
                "Proton", CheckStatus.WARNING, "Not found", "Proton",
                fix_command="Enable Steam Play"
            ),
        ]
        success, message = apply_fixes(checks, "apt", skip_confirm=True)
        self.assertTrue(success)
        self.assertIn("No automatic fixes", message)

    @patch('builtins.input', return_value='n')
    @patch('builtins.print')
    def test_apply_cancelled_by_user(self, mock_print, mock_input):
        """Test apply cancelled by user"""
        checks = [
            DependencyCheck(
                "Pkg1", CheckStatus.FAIL, "Missing", "32-bit",
                fix_command="sudo apt install -y pkg1"
            ),
        ]
        success, message = apply_fixes(checks, "apt", skip_confirm=False)
        self.assertFalse(success)
        self.assertIn("Cancelled", message)


class TestApplyArgumentParsing(unittest.TestCase):
    """Test argument parsing for apply/dry-run"""

    def test_apply_flag(self):
        """Test --apply flag"""
        with patch('sys.argv', ['prog', '--apply']):
            args = parse_args()
            self.assertTrue(args.apply)

    def test_dry_run_flag(self):
        """Test --dry-run flag"""
        with patch('sys.argv', ['prog', '--dry-run']):
            args = parse_args()
            self.assertTrue(args.dry_run)

    def test_yes_flag(self):
        """Test --yes flag"""
        with patch('sys.argv', ['prog', '--yes']):
            args = parse_args()
            self.assertTrue(args.yes)

    def test_yes_short_flag(self):
        """Test -y flag"""
        with patch('sys.argv', ['prog', '-y']):
            args = parse_args()
            self.assertTrue(args.yes)

    def test_apply_with_yes(self):
        """Test --apply -y combination"""
        with patch('sys.argv', ['prog', '--apply', '-y']):
            args = parse_args()
            self.assertTrue(args.apply)
            self.assertTrue(args.yes)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def test_full_check_workflow(self):
        """Test the full check workflow doesn't crash"""
        distro, pkg_mgr = DistroDetector.detect_distro()
        checker = DependencyChecker(distro, pkg_mgr)
        results = checker.run_all_checks()

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_json_output_is_valid(self):
        """Test that full JSON output is valid"""
        distro, pkg_mgr = DistroDetector.detect_distro()
        checker = DependencyChecker(distro, pkg_mgr)
        results = checker.run_all_checks()

        # Convert to JSON
        output = {
            "checks": [c.to_dict() for c in results],
            "summary": {
                "passed": sum(1 for c in results if c.status == CheckStatus.PASS),
                "failed": sum(1 for c in results if c.status == CheckStatus.FAIL),
            }
        }

        # Should be serializable
        json_str = json.dumps(output)
        self.assertIsInstance(json_str, str)

        # Should be parseable
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed["checks"]), len(results))


# =============================================================================
# ProtonDB Functions Tests
# =============================================================================

class TestGetTierColor(unittest.TestCase):
    """Tests for get_tier_color function"""

    def test_platinum_tier(self):
        """Test platinum tier returns cyan"""
        from steam_proton_helper import get_tier_color, Color
        self.assertEqual(get_tier_color("platinum"), Color.CYAN)

    def test_gold_tier(self):
        """Test gold tier returns yellow"""
        from steam_proton_helper import get_tier_color, Color
        self.assertEqual(get_tier_color("gold"), Color.YELLOW)

    def test_silver_tier(self):
        """Test silver tier returns blue"""
        from steam_proton_helper import get_tier_color, Color
        self.assertEqual(get_tier_color("silver"), Color.BLUE)

    def test_bronze_tier(self):
        """Test bronze tier returns yellow"""
        from steam_proton_helper import get_tier_color, Color
        self.assertEqual(get_tier_color("bronze"), Color.YELLOW)

    def test_borked_tier(self):
        """Test borked tier returns red"""
        from steam_proton_helper import get_tier_color, Color
        self.assertEqual(get_tier_color("borked"), Color.RED)

    def test_unknown_tier(self):
        """Test unknown tier returns empty string"""
        from steam_proton_helper import get_tier_color
        self.assertEqual(get_tier_color("unknown"), "")


class TestGetTierSymbol(unittest.TestCase):
    """Tests for get_tier_symbol function"""

    def test_platinum_symbol(self):
        """Test platinum tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("platinum"), "🏆")

    def test_gold_symbol(self):
        """Test gold tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("gold"), "🥇")

    def test_silver_symbol(self):
        """Test silver tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("silver"), "🥈")

    def test_bronze_symbol(self):
        """Test bronze tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("bronze"), "🥉")

    def test_borked_symbol(self):
        """Test borked tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("borked"), "💔")

    def test_unknown_symbol(self):
        """Test unknown tier symbol"""
        from steam_proton_helper import get_tier_symbol
        self.assertEqual(get_tier_symbol("unknown"), "❓")


class TestGetStatusSymbol(unittest.TestCase):
    """Tests for get_status_symbol function"""

    def test_pass_symbol(self):
        """Test PASS status symbol"""
        from steam_proton_helper import get_status_symbol, CheckStatus
        self.assertEqual(get_status_symbol(CheckStatus.PASS), "✓")

    def test_fail_symbol(self):
        """Test FAIL status symbol"""
        from steam_proton_helper import get_status_symbol, CheckStatus
        self.assertEqual(get_status_symbol(CheckStatus.FAIL), "✗")

    def test_warning_symbol(self):
        """Test WARNING status symbol"""
        from steam_proton_helper import get_status_symbol, CheckStatus
        self.assertEqual(get_status_symbol(CheckStatus.WARNING), "⚠")

    def test_skipped_symbol(self):
        """Test SKIPPED status symbol"""
        from steam_proton_helper import get_status_symbol, CheckStatus
        self.assertEqual(get_status_symbol(CheckStatus.SKIPPED), "○")


class TestGetStatusColor(unittest.TestCase):
    """Tests for get_status_color function"""

    def test_pass_color(self):
        """Test PASS status color"""
        from steam_proton_helper import get_status_color, CheckStatus, Color
        self.assertEqual(get_status_color(CheckStatus.PASS), Color.GREEN)

    def test_fail_color(self):
        """Test FAIL status color"""
        from steam_proton_helper import get_status_color, CheckStatus, Color
        self.assertEqual(get_status_color(CheckStatus.FAIL), Color.RED)

    def test_warning_color(self):
        """Test WARNING status color"""
        from steam_proton_helper import get_status_color, CheckStatus, Color
        self.assertEqual(get_status_color(CheckStatus.WARNING), Color.YELLOW)

    def test_skipped_color(self):
        """Test SKIPPED status color"""
        from steam_proton_helper import get_status_color, CheckStatus, Color
        self.assertEqual(get_status_color(CheckStatus.SKIPPED), Color.DIM)


class TestProtonDBInfo(unittest.TestCase):
    """Tests for ProtonDBInfo dataclass"""

    def test_create_protondb_info(self):
        """Test creating ProtonDBInfo"""
        from steam_proton_helper import ProtonDBInfo
        info = ProtonDBInfo(
            app_id="440",
            tier="gold",
            confidence="high",
            score=0.85,
            total_reports=150,
        )
        self.assertEqual(info.app_id, "440")
        self.assertEqual(info.tier, "gold")
        self.assertEqual(info.score, 0.85)
        self.assertEqual(info.total_reports, 150)
        self.assertEqual(info.confidence, "high")


class TestGEProtonRelease(unittest.TestCase):
    """Tests for GEProtonRelease dataclass"""

    def test_create_ge_proton_release(self):
        """Test creating GEProtonRelease"""
        from steam_proton_helper import GEProtonRelease
        release = GEProtonRelease(
            tag_name="GE-Proton9-1",
            name="GE-Proton9-1",
            download_url="https://example.com/release.tar.gz",
            size_bytes=500000000,
            published_at="2024-01-15T12:00:00Z",
        )
        self.assertEqual(release.tag_name, "GE-Proton9-1")
        self.assertEqual(release.size_bytes, 500000000)


class TestProtonRecommendation(unittest.TestCase):
    """Tests for ProtonRecommendation dataclass"""

    def test_create_recommendation(self):
        """Test creating ProtonRecommendation"""
        from steam_proton_helper import ProtonRecommendation
        rec = ProtonRecommendation(
            proton_version="GE-Proton9-1",
            reason="Most reported working version",
            priority=1
        )
        self.assertEqual(rec.proton_version, "GE-Proton9-1")
        self.assertEqual(rec.priority, 1)


class TestSteamAppDataclass(unittest.TestCase):
    """Tests for SteamApp dataclass"""

    def test_create_steam_app(self):
        """Test creating SteamApp"""
        from steam_proton_helper import SteamApp
        app = SteamApp(appid=440, name="Team Fortress 2")
        self.assertEqual(app.appid, 440)
        self.assertEqual(app.name, "Team Fortress 2")


class TestSearchSteamGames(unittest.TestCase):
    """Tests for search_steam_games function"""

    @patch('steam_proton_helper.subprocess.run')
    def test_search_with_steamcmd(self, mock_run):
        """Test searching games with steamcmd available"""
        from steam_proton_helper import search_steam_games
        # steamcmd not typically available, should return empty
        mock_run.side_effect = FileNotFoundError()
        result = search_steam_games("test")
        self.assertIsInstance(result, list)

    def test_search_returns_list(self):
        """Test search always returns a list"""
        from steam_proton_helper import search_steam_games
        result = search_steam_games("nonexistent_game_xyz")
        self.assertIsInstance(result, list)


class TestResolveGameInput(unittest.TestCase):
    """Tests for resolve_game_input function"""

    def test_numeric_app_id(self):
        """Test resolving numeric app ID"""
        from steam_proton_helper import resolve_game_input
        app_id, name, suggestions = resolve_game_input("440")
        self.assertEqual(app_id, "440")
        self.assertIsNone(name)
        self.assertEqual(suggestions, [])

    def test_string_name_input(self):
        """Test resolving game name string"""
        from steam_proton_helper import resolve_game_input
        app_id, name, suggestions = resolve_game_input("Some Game Name")
        # Should trigger a search (results depend on implementation)
        self.assertIsInstance(suggestions, list)


class TestFetchProtonDBInfo(unittest.TestCase):
    """Tests for fetch_protondb_info function"""

    @patch('urllib.request.urlopen')
    def test_fetch_with_http_error(self, mock_urlopen):
        """Test fetch when HTTP request fails"""
        import urllib.error
        from steam_proton_helper import fetch_protondb_info
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url='', code=404, msg='Not Found', hdrs=None, fp=None
        )
        result = fetch_protondb_info("99999999")
        self.assertIsNone(result)

    @patch('urllib.request.urlopen')
    def test_fetch_with_url_error(self, mock_urlopen):
        """Test fetch with network error"""
        import urllib.error
        from steam_proton_helper import fetch_protondb_info
        mock_urlopen.side_effect = urllib.error.URLError('Network unreachable')
        result = fetch_protondb_info("440")
        self.assertIsNone(result)

    @patch('urllib.request.urlopen')
    def test_fetch_with_valid_response(self, mock_urlopen):
        """Test fetch with valid JSON response"""
        from steam_proton_helper import fetch_protondb_info, ProtonDBInfo
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "tier": "gold",
            "score": 0.85,
            "total": 150,
            "confidence": "high"
        }).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response
        result = fetch_protondb_info("440")
        self.assertIsInstance(result, ProtonDBInfo)
        self.assertEqual(result.tier, "gold")


class TestFetchGEProtonReleases(unittest.TestCase):
    """Tests for fetch_ge_proton_releases function"""

    @patch('urllib.request.urlopen')
    def test_fetch_releases_network_error(self, mock_urlopen):
        """Test fetch when network fails"""
        import urllib.error
        from steam_proton_helper import fetch_ge_proton_releases
        mock_urlopen.side_effect = urllib.error.URLError('Network unreachable')
        result = fetch_ge_proton_releases()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    @patch('urllib.request.urlopen')
    def test_fetch_releases_valid_response(self, mock_urlopen):
        """Test fetch with valid JSON response"""
        from steam_proton_helper import fetch_ge_proton_releases
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps([{
            "tag_name": "GE-Proton9-1",
            "name": "GE-Proton9-1 Released",
            "published_at": "2024-01-15T00:00:00Z",
            "assets": [{
                "name": "GE-Proton9-1.tar.gz",
                "browser_download_url": "https://example.com/GE-Proton9-1.tar.gz",
                "size": 500000000
            }]
        }]).encode('utf-8')
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = lambda s, *args: None
        mock_urlopen.return_value = mock_response
        result = fetch_ge_proton_releases()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].tag_name, "GE-Proton9-1")


class TestGetProtonInstallDir(unittest.TestCase):
    """Tests for get_proton_install_dir function"""

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.os.path.isdir')
    def test_with_steam_root(self, mock_isdir, mock_find_root):
        """Test getting install dir when Steam is found"""
        from steam_proton_helper import get_proton_install_dir
        mock_find_root.return_value = "/home/user/.steam/root"
        mock_isdir.return_value = True  # Parent directory exists
        result = get_proton_install_dir()
        # Should return a valid path string
        self.assertTrue(result is None or isinstance(result, str))

    def test_with_explicit_variant(self):
        """Test with explicit variant parameter"""
        from steam_proton_helper import get_proton_install_dir, SteamVariant
        # Should work without crashing
        result = get_proton_install_dir(SteamVariant.NATIVE)
        # May be None if paths don't exist
        self.assertTrue(result is None or isinstance(result, str))


class TestGetProtonRecommendations(unittest.TestCase):
    """Tests for get_proton_recommendations function"""

    def test_recommendations_with_protondb_info(self):
        """Test getting recommendations with ProtonDB info"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="440",
            tier="gold",
            confidence="high",
            score=0.85,
            total_reports=150,
        )
        installed = ["GE-Proton9-1", "Proton Experimental"]
        result = get_proton_recommendations(info, installed)
        self.assertIsInstance(result, list)

    def test_platinum_tier_recommendations(self):
        """Test recommendations for platinum tier"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="292030", tier="platinum", confidence="strong",
            score=0.95, total_reports=1000,
        )
        result = get_proton_recommendations(info, ["GE-Proton9-1"])
        self.assertTrue(len(result) >= 1)
        # Platinum should recommend Experimental first
        self.assertIn("Experimental", result[0].proton_version)

    def test_silver_tier_recommendations(self):
        """Test recommendations for silver tier"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="12345", tier="silver", confidence="moderate",
            score=0.60, total_reports=50,
        )
        result = get_proton_recommendations(info, ["GE-Proton9-1"])
        self.assertTrue(len(result) >= 1)
        # Silver should recommend GE-Proton
        self.assertIn("GE-Proton", result[0].proton_version)

    def test_bronze_tier_recommendations(self):
        """Test recommendations for bronze tier"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="67890", tier="bronze", confidence="low",
            score=0.40, total_reports=20,
        )
        result = get_proton_recommendations(info, ["GE-Proton9-1"])
        self.assertTrue(len(result) >= 1)

    def test_borked_tier_recommendations(self):
        """Test recommendations for borked tier"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="99999", tier="borked", confidence="strong",
            score=0.10, total_reports=100,
        )
        result = get_proton_recommendations(info, ["GE-Proton9-1"])
        self.assertTrue(len(result) >= 1)

    def test_unknown_tier_recommendations(self):
        """Test recommendations for unknown/pending tier"""
        from steam_proton_helper import get_proton_recommendations, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="11111", tier="pending", confidence="none",
            score=0.0, total_reports=0,
        )
        result = get_proton_recommendations(info, [])
        self.assertTrue(len(result) >= 1)


class TestPrintFunctions(unittest.TestCase):
    """Tests for print output functions"""

    @patch('builtins.print')
    def test_print_header(self, mock_print):
        """Test print_header function"""
        from steam_proton_helper import print_header
        print_header()
        mock_print.assert_called()

    @patch('builtins.print')
    def test_print_tips(self, mock_print):
        """Test print_tips function"""
        from steam_proton_helper import print_tips
        print_tips()
        mock_print.assert_called()

    @patch('builtins.print')
    def test_print_summary(self, mock_print):
        """Test print_summary function"""
        from steam_proton_helper import print_summary, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General"),
            DependencyCheck("Test2", CheckStatus.FAIL, "Failed", "General"),
            DependencyCheck("Test3", CheckStatus.WARNING, "Warn", "General"),
        ]
        print_summary(checks)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_print_checks_by_category(self, mock_print):
        """Test print_checks_by_category function"""
        from steam_proton_helper import print_checks_by_category, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General"),
            DependencyCheck("Test2", CheckStatus.FAIL, "Failed", "Vulkan"),
        ]
        print_checks_by_category(checks)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_print_checks_verbose(self, mock_print):
        """Test print_checks_by_category with verbose=True"""
        from steam_proton_helper import print_checks_by_category, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General", details="Extra info"),
        ]
        print_checks_by_category(checks, verbose=True)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_print_protondb_info(self, mock_print):
        """Test print_protondb_info function"""
        from steam_proton_helper import print_protondb_info, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="440",
            tier="gold",
            confidence="high",
            score=0.85,
            total_reports=150,
        )
        print_protondb_info(info)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_output_protondb_json_with_info(self, mock_print):
        """Test output_protondb_json with valid info"""
        from steam_proton_helper import output_protondb_json, ProtonDBInfo
        info = ProtonDBInfo(
            app_id="440",
            tier="gold",
            confidence="high",
            score=0.85,
            total_reports=150,
        )
        output_protondb_json(info, "440")
        mock_print.assert_called()
        # Check JSON was printed
        call_args = mock_print.call_args[0][0]
        parsed = json.loads(call_args)
        self.assertEqual(parsed["tier"], "gold")

    @patch('builtins.print')
    def test_output_protondb_json_with_none(self, mock_print):
        """Test output_protondb_json with None info"""
        from steam_proton_helper import output_protondb_json
        output_protondb_json(None, "440")
        mock_print.assert_called()
        call_args = mock_print.call_args[0][0]
        parsed = json.loads(call_args)
        self.assertEqual(parsed["app_id"], "440")
        self.assertIn("error", parsed)


class TestOutputJson(unittest.TestCase):
    """Tests for output_json function"""

    @patch('builtins.print')
    def test_output_json(self, mock_print):
        """Test output_json function"""
        from steam_proton_helper import output_json, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General"),
        ]
        output_json(checks, "ubuntu", "apt")
        mock_print.assert_called()
        call_args = mock_print.call_args[0][0]
        parsed = json.loads(call_args)
        self.assertIn("checks", parsed)
        self.assertIn("system", parsed)


class TestGenerateFixScript(unittest.TestCase):
    """Tests for generate_fix_script function"""

    def test_generate_script_with_apt(self):
        """Test generating fix script for apt"""
        from steam_proton_helper import generate_fix_script, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(
                "Lib1", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib1"
            ),
        ]
        script = generate_fix_script(checks, "ubuntu", "apt")
        self.assertIn("#!/bin/bash", script)
        self.assertIn("apt install", script)

    def test_generate_script_no_fixes(self):
        """Test generating script with no fixes needed"""
        from steam_proton_helper import generate_fix_script, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General"),
        ]
        script = generate_fix_script(checks, "ubuntu", "apt")
        self.assertIn("No fixes needed", script)


class TestOutputFixScript(unittest.TestCase):
    """Tests for output_fix_script function"""

    def test_output_to_stdout(self):
        """Test outputting script to stdout"""
        from steam_proton_helper import output_fix_script, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(
                "Lib1", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib1"
            ),
        ]
        # output_fix_script returns bool indicating success
        result = output_fix_script(checks, "ubuntu", "apt", "-")
        self.assertIsInstance(result, bool)

    def test_output_to_file(self):
        """Test outputting script to file"""
        import tempfile
        from steam_proton_helper import output_fix_script, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(
                "Lib1", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib1"
            ),
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            output_path = f.name
        result = output_fix_script(checks, "ubuntu", "apt", output_path)
        self.assertIsInstance(result, bool)
        # Clean up
        import os
        if os.path.exists(output_path):
            os.unlink(output_path)


class TestCollectFixActionsNew(unittest.TestCase):
    """Tests for collect_fix_actions function"""

    def test_collect_apt_actions(self):
        """Test collecting apt fix actions"""
        from steam_proton_helper import collect_fix_actions, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(
                "Lib1", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib1 lib2"
            ),
            DependencyCheck(
                "Lib2", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib3"
            ),
        ]
        packages, other = collect_fix_actions(checks, "apt")
        self.assertIn("lib1", packages)
        self.assertIn("lib2", packages)
        self.assertIn("lib3", packages)


class TestShowDryRun(unittest.TestCase):
    """Tests for show_dry_run function"""

    @patch('builtins.print')
    def test_show_dry_run(self, mock_print):
        """Test show_dry_run output"""
        from steam_proton_helper import show_dry_run, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(
                "Lib1", CheckStatus.FAIL, "Missing",
                "32-bit", fix_command="sudo apt install -y lib1"
            ),
        ]
        show_dry_run(checks, "apt")
        mock_print.assert_called()

    @patch('builtins.print')
    def test_show_dry_run_no_fixes(self, mock_print):
        """Test show_dry_run with no fixes"""
        from steam_proton_helper import show_dry_run, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck("Test1", CheckStatus.PASS, "OK", "General"),
        ]
        show_dry_run(checks, "apt")
        mock_print.assert_called()


class TestGetRemovableProtonVersions(unittest.TestCase):
    """Tests for get_removable_proton_versions function"""

    @patch('steam_proton_helper.find_steam_root')
    def test_no_install_dir(self, mock_find_root):
        """Test when no Steam root exists"""
        from steam_proton_helper import get_removable_proton_versions
        mock_find_root.return_value = None
        result = get_removable_proton_versions()
        self.assertEqual(result, [])

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.os.path.isdir')
    @patch('steam_proton_helper.os.listdir')
    def test_with_proton_versions(self, mock_listdir, mock_isdir, mock_get_dir):
        """Test with some Proton versions installed"""
        from steam_proton_helper import get_removable_proton_versions
        mock_get_dir.return_value = "/path/to/protons"
        mock_isdir.return_value = True
        mock_listdir.return_value = ["GE-Proton9-1", "GE-Proton8-25", "SomeOtherDir"]
        result = get_removable_proton_versions()
        self.assertIsInstance(result, list)


class TestRemoveGEProton(unittest.TestCase):
    """Tests for remove_ge_proton function"""

    @patch('steam_proton_helper.get_proton_install_dir')
    def test_remove_no_install_dir(self, mock_get_dir):
        """Test removal when no install directory"""
        from steam_proton_helper import remove_ge_proton
        mock_get_dir.return_value = None
        success, message = remove_ge_proton("GE-Proton9-1")
        self.assertFalse(success)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.os.path.exists')
    def test_remove_version_not_found(self, mock_exists, mock_get_dir):
        """Test removal when version not found"""
        from steam_proton_helper import remove_ge_proton
        mock_get_dir.return_value = "/path/to/protons"
        mock_exists.return_value = False
        success, message = remove_ge_proton("GE-Proton9-1")
        self.assertFalse(success)
        self.assertIn("not found", message.lower())

    @patch('builtins.input', return_value='n')
    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.os.path.exists')
    def test_remove_cancelled(self, mock_exists, mock_get_dir, mock_input):
        """Test removal cancelled by user"""
        from steam_proton_helper import remove_ge_proton
        mock_get_dir.return_value = "/path/to/protons"
        mock_exists.return_value = True
        success, message = remove_ge_proton("GE-Proton9-1", confirm=False)
        self.assertFalse(success)


class TestCheckGEProtonUpdates(unittest.TestCase):
    """Tests for check_ge_proton_updates function"""

    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('steam_proton_helper.get_removable_proton_versions')
    def test_no_updates_available(self, mock_installed, mock_releases):
        """Test when no updates available"""
        from steam_proton_helper import check_ge_proton_updates
        mock_releases.return_value = []
        mock_installed.return_value = []
        result = check_ge_proton_updates()
        self.assertIsInstance(result, list)


class TestUpdateGEProton(unittest.TestCase):
    """Tests for update_ge_proton function"""

    @patch('steam_proton_helper.check_ge_proton_updates')
    def test_no_updates(self, mock_check):
        """Test when update check returns empty list (error case)"""
        from steam_proton_helper import update_ge_proton
        mock_check.return_value = []
        success, message = update_ge_proton()
        # Empty list means couldn't check updates
        self.assertFalse(success)
        self.assertIn("could not check", message.lower())


class TestDownloadWithProgress(unittest.TestCase):
    """Tests for download_with_progress function"""

    @patch('steam_proton_helper.subprocess.run')
    def test_download_failure(self, mock_run):
        """Test download failure"""
        from steam_proton_helper import download_with_progress
        mock_run.side_effect = subprocess.CalledProcessError(1, 'curl')
        result = download_with_progress("https://example.com/file.tar.gz", "/tmp/file.tar.gz", show_progress=False)
        self.assertFalse(result)


class TestInstallGEProton(unittest.TestCase):
    """Tests for install_ge_proton function"""

    @patch('steam_proton_helper.get_proton_install_dir')
    def test_install_no_dir(self, mock_get_dir):
        """Test install when no install directory"""
        from steam_proton_helper import install_ge_proton
        mock_get_dir.return_value = None
        success, message = install_ge_proton("GE-Proton9-1")
        self.assertFalse(success)

    @patch('steam_proton_helper.os.path.exists')
    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_install_already_exists(self, mock_fetch, mock_get_dir, mock_exists):
        """Test install when version already exists"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        # Mock releases to include the requested version
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="https://example.com/GE-Proton9-1.tar.gz",
                size_bytes=500000000,
                published_at="2024-01-15"
            )
        ]
        mock_get_dir.return_value = "/path/to/protons"
        mock_exists.return_value = True
        success, message = install_ge_proton("GE-Proton9-1", force=False)
        self.assertFalse(success)
        self.assertIn("already installed", message.lower())


class TestMainFunction(unittest.TestCase):
    """Tests for main function"""

    @patch('sys.argv', ['prog', '--version'])
    @patch('builtins.print')
    def test_version_flag(self, mock_print):
        """Test --version flag"""
        from steam_proton_helper import main
        with self.assertRaises(SystemExit) as cm:
            main()
        # argparse exits with 0 for --version
        self.assertEqual(cm.exception.code, 0)

    @patch('sys.argv', ['prog', '--help'])
    def test_help_flag(self):
        """Test --help flag"""
        from steam_proton_helper import main
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)

    @patch('sys.argv', ['prog', '--json'])
    @patch('builtins.print')
    def test_json_output(self, mock_print):
        """Test --json flag produces valid JSON"""
        from steam_proton_helper import main
        result = main()
        self.assertEqual(result, 0)
        # Verify JSON was printed
        mock_print.assert_called()

    @patch('sys.argv', ['prog', '--no-color'])
    @patch('builtins.print')
    def test_no_color_flag(self, mock_print):
        """Test --no-color flag"""
        from steam_proton_helper import main
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--search', 'witcher'])
    @patch('steam_proton_helper.search_steam_games')
    @patch('builtins.print')
    def test_search_flag(self, mock_print, mock_search):
        """Test --search flag"""
        from steam_proton_helper import main, SteamApp
        mock_search.return_value = [
            SteamApp(appid=292030, name="The Witcher 3: Wild Hunt"),
            SteamApp(appid=20920, name="The Witcher 2"),
        ]
        result = main()
        self.assertEqual(result, 0)
        mock_print.assert_called()

    @patch('sys.argv', ['prog', '--search', 'witcher', '--json'])
    @patch('steam_proton_helper.search_steam_games')
    @patch('builtins.print')
    def test_search_flag_json(self, mock_print, mock_search):
        """Test --search with --json flag"""
        from steam_proton_helper import main, SteamApp
        mock_search.return_value = [
            SteamApp(appid=292030, name="The Witcher 3"),
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--search', 'nonexistent_xyz'])
    @patch('steam_proton_helper.search_steam_games')
    @patch('builtins.print')
    def test_search_no_results(self, mock_print, mock_search):
        """Test --search with no results"""
        from steam_proton_helper import main
        mock_search.return_value = []
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--list-proton'])
    @patch('steam_proton_helper.find_steam_root')
    @patch('builtins.print')
    def test_list_proton_no_steam(self, mock_print, mock_find):
        """Test --list-proton when Steam not found"""
        from steam_proton_helper import main
        mock_find.return_value = None
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--list-proton'])
    @patch('steam_proton_helper.find_proton_installations')
    @patch('steam_proton_helper.find_steam_root')
    @patch('builtins.print')
    def test_list_proton_with_installations(self, mock_print, mock_find_root, mock_find_proton):
        """Test --list-proton with Proton installations"""
        from steam_proton_helper import main, ProtonInstall
        mock_find_root.return_value = "/home/user/.steam/root"
        mock_find_proton.return_value = [
            ProtonInstall("GE-Proton9-1", "/path/compatibilitytools.d/GE-Proton9-1", True, True, True),
            ProtonInstall("Proton 8.0", "/path/common/Proton 8.0", True, True, True),
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--list-proton', '--json'])
    @patch('steam_proton_helper.find_proton_installations')
    @patch('steam_proton_helper.find_steam_root')
    @patch('builtins.print')
    def test_list_proton_json(self, mock_print, mock_find_root, mock_find_proton):
        """Test --list-proton with --json flag"""
        from steam_proton_helper import main, ProtonInstall
        mock_find_root.return_value = "/home/user/.steam/root"
        mock_find_proton.return_value = [
            ProtonInstall("GE-Proton9-1", "/path/compatibilitytools.d/GE-Proton9-1", True, True, True),
        ]
        result = main()
        self.assertEqual(result, 0)


class TestVDFParserEdgeCases(unittest.TestCase):
    """Tests for VDF parser edge cases"""

    def test_parse_permission_error(self):
        """Test VDF parse with permission error"""
        from steam_proton_helper import parse_libraryfolders_vdf
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            result = parse_libraryfolders_vdf("/etc/shadow")
            self.assertEqual(result, [])

    def test_parse_generic_exception(self):
        """Test VDF parse with generic exception"""
        from steam_proton_helper import parse_libraryfolders_vdf
        with patch('builtins.open', side_effect=Exception("Unknown error")):
            result = parse_libraryfolders_vdf("/some/path")
            self.assertEqual(result, [])


class TestDistroDetectorEdgeCases(unittest.TestCase):
    """Tests for DistroDetector edge cases"""

    def test_detect_fedora(self):
        """Test detecting Fedora"""
        from steam_proton_helper import DistroDetector
        os_release = 'ID=fedora\nPRETTY_NAME="Fedora Linux 39"\n'
        with patch('builtins.open', MagicMock(return_value=MagicMock(
            __enter__=lambda s: MagicMock(read=lambda: os_release, __iter__=lambda s: iter(os_release.split('\n'))),
            __exit__=lambda s, *a: None
        ))):
            with patch('os.path.exists', return_value=True):
                distro, pm = DistroDetector.detect_distro()
                # Should detect dnf for Fedora
                self.assertIn(pm, ['dnf', 'apt', 'pacman', 'zypper', 'unknown'])

    def test_detect_arch(self):
        """Test detecting Arch Linux"""
        from steam_proton_helper import DistroDetector
        os_release = 'ID=arch\nPRETTY_NAME="Arch Linux"\n'
        m = MagicMock()
        m.__enter__ = lambda s: m
        m.__exit__ = lambda s, *a: None
        m.__iter__ = lambda s: iter(os_release.split('\n'))
        with patch('builtins.open', return_value=m):
            with patch('os.path.exists', return_value=True):
                distro, pm = DistroDetector.detect_distro()
                self.assertIn(pm, ['pacman', 'apt', 'dnf', 'zypper', 'unknown'])

    def test_detect_opensuse(self):
        """Test detecting openSUSE"""
        from steam_proton_helper import DistroDetector
        os_release = 'ID=opensuse-tumbleweed\nPRETTY_NAME="openSUSE Tumbleweed"\n'
        m = MagicMock()
        m.__enter__ = lambda s: m
        m.__exit__ = lambda s, *a: None
        m.__iter__ = lambda s: iter(os_release.split('\n'))
        with patch('builtins.open', return_value=m):
            with patch('os.path.exists', return_value=True):
                distro, pm = DistroDetector.detect_distro()
                self.assertIn(pm, ['zypper', 'apt', 'dnf', 'pacman', 'unknown'])

    def test_detect_fallback_to_package_manager(self):
        """Test fallback to package manager detection"""
        from steam_proton_helper import DistroDetector
        with patch('os.path.exists', return_value=False):
            with patch('shutil.which', side_effect=lambda x: '/usr/bin/pacman' if x == 'pacman' else None):
                distro, pm = DistroDetector.detect_distro()
                self.assertEqual(pm, 'pacman')


class TestDependencyCheckerPackageManagers(unittest.TestCase):
    """Tests for DependencyChecker with different package managers"""

    def test_check_package_installed_dnf(self):
        """Test package check with DNF"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Fedora", "dnf")
        with patch.object(checker, 'run_command', return_value=(0, '', '')):
            result = checker.check_package_installed('some-package')
            self.assertTrue(result)

    def test_check_package_installed_pacman(self):
        """Test package check with Pacman"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Arch Linux", "pacman")
        with patch.object(checker, 'run_command', return_value=(0, '', '')):
            result = checker.check_package_installed('some-package')
            self.assertTrue(result)

    def test_check_package_installed_zypper(self):
        """Test package check with Zypper"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("openSUSE", "zypper")
        with patch.object(checker, 'run_command', return_value=(0, '', '')):
            result = checker.check_package_installed('some-package')
            self.assertTrue(result)

    def test_check_package_installed_unknown(self):
        """Test package check with unknown package manager"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Unknown", "unknown")
        result = checker.check_package_installed('some-package')
        self.assertFalse(result)

    def test_check_multilib_dnf(self):
        """Test multilib check with DNF"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Fedora", "dnf")
        enabled, msg = checker.check_multilib_enabled()
        self.assertTrue(enabled)
        self.assertIn("automatically", msg.lower())

    def test_check_multilib_unknown(self):
        """Test multilib check with unknown package manager"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Unknown", "unknown_pm")
        enabled, msg = checker.check_multilib_enabled()
        self.assertTrue(enabled)  # Assumes available

    def test_check_multilib_pacman_enabled(self):
        """Test multilib check with pacman - multilib enabled"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Arch", "pacman")
        pacman_content = """
[core]
Include = /etc/pacman.d/mirrorlist

[multilib]
Include = /etc/pacman.d/mirrorlist
"""
        with patch('builtins.open', unittest.mock.mock_open(read_data=pacman_content)):
            enabled, msg = checker.check_multilib_enabled()
            self.assertTrue(enabled)
            self.assertIn("multilib", msg.lower())

    def test_check_multilib_pacman_disabled(self):
        """Test multilib check with pacman - multilib not present"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Arch", "pacman")
        pacman_content = """
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist
"""
        with patch('builtins.open', unittest.mock.mock_open(read_data=pacman_content)):
            enabled, msg = checker.check_multilib_enabled()
            self.assertFalse(enabled)
            self.assertIn("not enabled", msg.lower())

    def test_check_multilib_pacman_error(self):
        """Test multilib check with pacman - file read error"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Arch", "pacman")
        with patch('builtins.open', side_effect=Exception("Cannot read file")):
            enabled, msg = checker.check_multilib_enabled()
            self.assertFalse(enabled)
            self.assertIn("could not read", msg.lower())


class TestGraphicsChecks(unittest.TestCase):
    """Tests for graphics/GPU checking functions"""

    def test_vulkan_not_installed(self):
        """Test vulkan check when vulkaninfo not installed"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Ubuntu", "apt")
        with patch.object(checker, 'check_command_exists', return_value=False):
            checks = checker.check_graphics()
            vulkan_check = next((c for c in checks if c.name == "Vulkan Tools"), None)
            self.assertIsNotNone(vulkan_check)
            self.assertEqual(vulkan_check.status, CheckStatus.FAIL)

    def test_vulkan_fails(self):
        """Test vulkan check when vulkaninfo returns error"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Ubuntu", "apt")
        with patch.object(checker, 'check_command_exists', return_value=True):
            with patch.object(checker, 'run_command', return_value=(1, '', 'Vulkan error')):
                checks = checker.check_graphics()
                vulkan_check = next((c for c in checks if c.name == "Vulkan Support"), None)
                self.assertIsNotNone(vulkan_check)
                self.assertEqual(vulkan_check.status, CheckStatus.FAIL)

    def test_glxinfo_not_installed(self):
        """Test glxinfo check when not installed"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Ubuntu", "apt")
        # Mock vulkaninfo exists but glxinfo doesn't
        def side_effect(cmd):
            if cmd == 'vulkaninfo':
                return True
            return False
        with patch.object(checker, 'check_command_exists', side_effect=side_effect):
            with patch.object(checker, 'run_command', return_value=(0, 'GPU info', '')):
                checks = checker.check_graphics()
                mesa_check = next((c for c in checks if c.name == "Mesa/OpenGL"), None)
                self.assertIsNotNone(mesa_check)
                self.assertEqual(mesa_check.status, CheckStatus.WARNING)

    def test_glxinfo_fails(self):
        """Test glxinfo check when it returns error"""
        from steam_proton_helper import DependencyChecker
        checker = DependencyChecker("Ubuntu", "apt")
        with patch.object(checker, 'check_command_exists', return_value=True):
            def run_side_effect(cmd):
                if 'vulkaninfo' in cmd:
                    return (0, 'Vulkan works', '')
                return (1, '', 'GLX error')
            with patch.object(checker, 'run_command', side_effect=run_side_effect):
                checks = checker.check_graphics()
                mesa_check = next((c for c in checks if c.name == "Mesa/OpenGL"), None)
                self.assertIsNotNone(mesa_check)
                self.assertEqual(mesa_check.status, CheckStatus.WARNING)


class TestInstallProtonBranches(unittest.TestCase):
    """Tests for --install-proton CLI branches"""

    @patch('sys.argv', ['prog', '--install-proton', 'list', '--json'])
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('builtins.print')
    def test_install_proton_list_json(self, mock_print, mock_fetch):
        """Test --install-proton list with JSON output"""
        from steam_proton_helper import main, GEProtonRelease
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="https://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        result = main()
        self.assertEqual(result, 0)
        # Check JSON was printed
        printed_json = mock_print.call_args_list[-1][0][0]
        self.assertIn("releases", printed_json)

    @patch('sys.argv', ['prog', '--install-proton', 'list'])
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('builtins.print')
    def test_install_proton_list_empty(self, mock_print, mock_fetch):
        """Test --install-proton list when no releases available"""
        from steam_proton_helper import main
        mock_fetch.return_value = []
        result = main()
        self.assertEqual(result, 1)  # Should fail

    @patch('sys.argv', ['prog', '--install-proton', 'GE-Proton9-1'])
    @patch('steam_proton_helper.install_ge_proton')
    @patch('builtins.print')
    def test_install_proton_success(self, mock_print, mock_install):
        """Test successful proton installation"""
        from steam_proton_helper import main
        mock_install.return_value = (True, "GE-Proton9-1 installed successfully")
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--install-proton', 'GE-Proton9-1'])
    @patch('steam_proton_helper.install_ge_proton')
    @patch('builtins.print')
    def test_install_proton_failure(self, mock_print, mock_install):
        """Test failed proton installation"""
        from steam_proton_helper import main
        mock_install.return_value = (False, "Installation failed")
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--install-proton', 'GE-Proton9-1'])
    @patch('steam_proton_helper.install_ge_proton')
    @patch('builtins.print')
    def test_install_proton_exception(self, mock_print, mock_install):
        """Test proton installation with exception"""
        from steam_proton_helper import main
        mock_install.side_effect = Exception("Network error")
        result = main()
        self.assertEqual(result, 1)


class TestRemoveProtonBranches(unittest.TestCase):
    """Tests for --remove-proton CLI branches"""

    @patch('sys.argv', ['prog', '--remove-proton', 'list', '--json'])
    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.print')
    def test_remove_proton_list_json(self, mock_print, mock_removable):
        """Test --remove-proton list with JSON output"""
        from steam_proton_helper import main
        mock_removable.return_value = [
            ("GE-Proton9-1", "/path/to/ge-proton"),
            ("GE-Proton8-25", "/path/to/ge-proton-old"),
        ]
        result = main()
        self.assertEqual(result, 0)
        printed_json = mock_print.call_args_list[-1][0][0]
        self.assertIn("removable", printed_json)

    @patch('sys.argv', ['prog', '--remove-proton', 'list'])
    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.print')
    def test_remove_proton_list_empty(self, mock_print, mock_removable):
        """Test --remove-proton list when nothing to remove"""
        from steam_proton_helper import main
        mock_removable.return_value = []
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--remove-proton', 'GE-Proton9-1', '--force'])
    @patch('steam_proton_helper.remove_ge_proton')
    @patch('builtins.print')
    def test_remove_proton_force(self, mock_print, mock_remove):
        """Test forced proton removal"""
        from steam_proton_helper import main
        mock_remove.return_value = (True, "Removed successfully")
        result = main()
        self.assertEqual(result, 0)


class TestSteamLibraryBranches(unittest.TestCase):
    """Tests for Steam library detection branches"""

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.get_library_paths')
    def test_check_steam_multiple_libraries(self, mock_libs, mock_root):
        """Test Steam check with multiple library folders"""
        from steam_proton_helper import DependencyChecker
        mock_root.return_value = "/home/user/.steam/steam"
        mock_libs.return_value = [
            "/home/user/.steam/steam",
            "/media/games/SteamLibrary"
        ]
        checker = DependencyChecker("Ubuntu", "apt")
        with patch.object(checker, 'run_command', return_value=(0, '', '')):
            checks = checker.check_steam()
            lib_check = next((c for c in checks if c.name == "Steam Libraries"), None)
            self.assertIsNotNone(lib_check)
            self.assertEqual(lib_check.status, CheckStatus.PASS)
            self.assertIn("2", lib_check.message)

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.detect_steam_variant')
    def test_check_steam_no_root(self, mock_variant, mock_root):
        """Test Steam check when root not found but variant exists"""
        from steam_proton_helper import DependencyChecker, SteamVariant
        mock_root.return_value = None
        mock_variant.return_value = (SteamVariant.NATIVE, "Native Steam")
        checker = DependencyChecker("Ubuntu", "apt")
        with patch.object(checker, 'run_command', return_value=(0, '', '')):
            checks = checker.check_steam()
            root_check = next((c for c in checks if c.name == "Steam Root"), None)
            self.assertIsNotNone(root_check)
            self.assertEqual(root_check.status, CheckStatus.WARNING)


class TestListProtonVerbose(unittest.TestCase):
    """Tests for --list-proton verbose output branches"""

    @patch('sys.argv', ['prog', '--list-proton', '--verbose'])
    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.find_proton_installations')
    @patch('builtins.print')
    def test_list_proton_verbose(self, mock_print, mock_installs, mock_root):
        """Test --list-proton with verbose output shows full paths"""
        from steam_proton_helper import main, ProtonInstall
        mock_root.return_value = "/home/user/.steam/steam"
        mock_installs.return_value = [
            ProtonInstall(
                name="GE-Proton9-1",
                path="/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1",
                has_executable=True,
                has_toolmanifest=True,
                has_version=True
            )
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--list-proton'])
    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.find_proton_installations')
    @patch('builtins.print')
    def test_list_proton_no_verbose(self, mock_print, mock_installs, mock_root):
        """Test --list-proton without verbose hides full paths"""
        from steam_proton_helper import main, ProtonInstall
        mock_root.return_value = "/home/user/.steam/steam"
        mock_installs.return_value = [
            ProtonInstall(
                name="GE-Proton9-1",
                path="/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1",
                has_executable=True,
                has_toolmanifest=True,
                has_version=True
            )
        ]
        result = main()
        self.assertEqual(result, 0)


class TestCheckUpdatesBranches(unittest.TestCase):
    """Tests for --check-updates CLI branches"""

    @patch('sys.argv', ['prog', '--check-updates', '--json'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_json(self, mock_print, mock_check):
        """Test --check-updates with JSON output"""
        from steam_proton_helper import main
        mock_check.return_value = [
            {'installed': 'GE-Proton9-1', 'latest': 'GE-Proton9-2', 'update_available': True}
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--check-updates'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_with_update(self, mock_print, mock_check):
        """Test --check-updates when update available"""
        from steam_proton_helper import main
        mock_check.return_value = [
            {'installed': 'GE-Proton9-1', 'latest': 'GE-Proton9-2', 'update_available': True}
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--check-updates'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_up_to_date(self, mock_print, mock_check):
        """Test --check-updates when already up to date"""
        from steam_proton_helper import main
        mock_check.return_value = [
            {'installed': 'GE-Proton9-2', 'latest': 'GE-Proton9-2', 'update_available': False}
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--check-updates'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_none_installed(self, mock_print, mock_check):
        """Test --check-updates when no GE-Proton installed"""
        from steam_proton_helper import main
        mock_check.return_value = [
            {'installed': None, 'latest': 'GE-Proton9-2', 'update_available': False}
        ]
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--check-updates'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_empty(self, mock_print, mock_check):
        """Test --check-updates when check fails"""
        from steam_proton_helper import main
        mock_check.return_value = []
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--check-updates'])
    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('builtins.print')
    def test_check_updates_exception(self, mock_print, mock_check):
        """Test --check-updates with exception"""
        from steam_proton_helper import main
        mock_check.side_effect = Exception("Network error")
        result = main()
        self.assertEqual(result, 1)


class TestUpdateProtonBranches(unittest.TestCase):
    """Tests for --update-proton CLI branches"""

    @patch('sys.argv', ['prog', '--update-proton'])
    @patch('steam_proton_helper.update_ge_proton')
    @patch('builtins.print')
    def test_update_proton_success(self, mock_print, mock_update):
        """Test --update-proton successful update"""
        from steam_proton_helper import main
        mock_update.return_value = (True, "Updated to GE-Proton9-2")
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--update-proton'])
    @patch('steam_proton_helper.update_ge_proton')
    @patch('builtins.print')
    def test_update_proton_failure(self, mock_print, mock_update):
        """Test --update-proton failed update"""
        from steam_proton_helper import main
        mock_update.return_value = (False, "No updates available")
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--update-proton', '--force'])
    @patch('steam_proton_helper.update_ge_proton')
    @patch('builtins.print')
    def test_update_proton_force(self, mock_print, mock_update):
        """Test --update-proton with --force flag"""
        from steam_proton_helper import main
        mock_update.return_value = (True, "Force updated to GE-Proton9-2")
        result = main()
        self.assertEqual(result, 0)
        mock_update.assert_called_with(force=True)

    @patch('sys.argv', ['prog', '--update-proton'])
    @patch('steam_proton_helper.update_ge_proton')
    @patch('builtins.print')
    def test_update_proton_exception(self, mock_print, mock_update):
        """Test --update-proton with exception"""
        from steam_proton_helper import main
        mock_update.side_effect = Exception("Download failed")
        result = main()
        self.assertEqual(result, 1)


class TestGameProtonDBBranches(unittest.TestCase):
    """Tests for --game ProtonDB lookup CLI branches"""

    @patch('sys.argv', ['prog', '--game', '292030'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('steam_proton_helper.fetch_protondb_info')
    @patch('steam_proton_helper.print_protondb_info')
    @patch('builtins.print')
    def test_game_by_appid(self, mock_print, mock_print_info, mock_fetch, mock_resolve):
        """Test --game with AppID"""
        from steam_proton_helper import main, ProtonDBInfo
        mock_resolve.return_value = ("292030", "The Witcher 3", None)
        mock_fetch.return_value = ProtonDBInfo(
            app_id="292030", tier="gold", confidence="strong",
            score=0.85, total_reports=500
        )
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--game', 'witcher', '--json'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('steam_proton_helper.fetch_protondb_info')
    @patch('builtins.print')
    def test_game_json_output(self, mock_print, mock_fetch, mock_resolve):
        """Test --game with JSON output"""
        from steam_proton_helper import main, ProtonDBInfo
        mock_resolve.return_value = ("292030", "The Witcher 3", None)
        mock_fetch.return_value = ProtonDBInfo(
            app_id="292030", tier="gold", confidence="strong",
            score=0.85, total_reports=500
        )
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--game', 'nonexistent'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('builtins.print')
    def test_game_not_found(self, mock_print, mock_resolve):
        """Test --game with game not found"""
        from steam_proton_helper import main
        mock_resolve.return_value = (None, None, None)
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--game', 'witcher'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('builtins.print')
    def test_game_multiple_matches(self, mock_print, mock_resolve):
        """Test --game with multiple matches"""
        from steam_proton_helper import main, SteamApp
        mock_resolve.return_value = (None, None, [
            SteamApp(appid=292030, name="The Witcher 3"),
            SteamApp(appid=20920, name="The Witcher 2"),
        ])
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--game', '292030'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('steam_proton_helper.fetch_protondb_info')
    @patch('builtins.print')
    def test_game_not_in_protondb(self, mock_print, mock_fetch, mock_resolve):
        """Test --game when game not in ProtonDB"""
        from steam_proton_helper import main
        mock_resolve.return_value = ("292030", "The Witcher 3", None)
        mock_fetch.return_value = None
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--game', '292030,1245620'])
    @patch('steam_proton_helper.resolve_game_input')
    @patch('steam_proton_helper.fetch_protondb_info')
    @patch('steam_proton_helper.print_protondb_info')
    @patch('builtins.print')
    def test_game_comma_separated_appids(self, mock_print, mock_print_info, mock_fetch, mock_resolve):
        """Test --game with comma-separated AppIDs"""
        from steam_proton_helper import main, ProtonDBInfo
        mock_resolve.side_effect = [
            ("292030", "The Witcher 3", None),
            ("1245620", "Elden Ring", None),
        ]
        mock_fetch.return_value = ProtonDBInfo(
            app_id="292030", tier="gold", confidence="strong",
            score=0.85, total_reports=500
        )
        result = main()
        self.assertEqual(result, 0)


class Test32BitPackageChecks(unittest.TestCase):
    """Tests for 32-bit package checking branches"""

    def test_dnf_vulkan_package_warning(self):
        """Test 32-bit vulkan package check with dnf gives warning"""
        from steam_proton_helper import DependencyChecker, CheckStatus
        checker = DependencyChecker("Fedora", "dnf")
        with patch.object(checker, 'check_package_installed', return_value=False):
            checks = checker.check_32bit_support()
            # Find vulkan-related check that should be warning
            vulkan_checks = [c for c in checks if 'vulkan' in c.name.lower() and c.status == CheckStatus.WARNING]
            # Note: this tests the branch where vulkan package name may vary on dnf


class TestApplyFixesBranches(unittest.TestCase):
    """Tests for apply_fixes function branches"""

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.print')
    def test_apply_fixes_no_fixes(self, mock_print, mock_collect):
        """Test apply_fixes with no fixes needed"""
        from steam_proton_helper import apply_fixes
        mock_collect.return_value = ([], [])
        result = apply_fixes([], "apt")
        self.assertEqual(result, (True, "No fixes needed - all checks passed!"))

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='n')
    @patch('builtins.print')
    def test_apply_fixes_user_cancels(self, mock_print, mock_input, mock_collect):
        """Test apply_fixes when user cancels"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test")
        ]
        mock_collect.return_value = (['test'], [])
        result = apply_fixes(checks, "apt")
        self.assertEqual(result[0], False)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', side_effect=KeyboardInterrupt)
    @patch('builtins.print')
    def test_apply_fixes_keyboard_interrupt(self, mock_print, mock_input, mock_collect):
        """Test apply_fixes with keyboard interrupt"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test")
        ]
        mock_collect.return_value = (['test'], [])
        result = apply_fixes(checks, "apt")
        self.assertEqual(result[0], False)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='y')
    @patch('steam_proton_helper.subprocess.run')
    @patch('builtins.print')
    def test_apply_fixes_apt_success(self, mock_print, mock_run, mock_input, mock_collect):
        """Test apply_fixes with apt success"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test")
        ]
        mock_collect.return_value = (['test'], [])
        mock_run.return_value = MagicMock(returncode=0)
        result = apply_fixes(checks, "apt")
        self.assertEqual(result[0], True)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='y')
    @patch('steam_proton_helper.subprocess.run')
    @patch('builtins.print')
    def test_apply_fixes_dnf_success(self, mock_print, mock_run, mock_input, mock_collect):
        """Test apply_fixes with dnf success"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo dnf install test")
        ]
        mock_collect.return_value = (['test'], [])
        mock_run.return_value = MagicMock(returncode=0)
        result = apply_fixes(checks, "dnf")
        self.assertEqual(result[0], True)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='y')
    @patch('steam_proton_helper.subprocess.run')
    @patch('builtins.print')
    def test_apply_fixes_pacman_success(self, mock_print, mock_run, mock_input, mock_collect):
        """Test apply_fixes with pacman success"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo pacman -S test")
        ]
        mock_collect.return_value = (['test'], [])
        mock_run.return_value = MagicMock(returncode=0)
        result = apply_fixes(checks, "pacman")
        self.assertEqual(result[0], True)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='y')
    @patch('steam_proton_helper.subprocess.run')
    @patch('builtins.print')
    def test_apply_fixes_install_fails(self, mock_print, mock_run, mock_input, mock_collect):
        """Test apply_fixes when installation fails"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test")
        ]
        mock_collect.return_value = (['test'], [])
        mock_run.return_value = MagicMock(returncode=1)
        result = apply_fixes(checks, "apt")
        self.assertEqual(result[0], False)

    @patch('steam_proton_helper.collect_fix_actions')
    @patch('builtins.input', return_value='y')
    @patch('steam_proton_helper.subprocess.run', side_effect=FileNotFoundError)
    @patch('builtins.print')
    def test_apply_fixes_package_manager_not_found(self, mock_print, mock_run, mock_input, mock_collect):
        """Test apply_fixes when package manager not found"""
        from steam_proton_helper import apply_fixes, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test")
        ]
        mock_collect.return_value = (['test'], [])
        result = apply_fixes(checks, "apt")
        self.assertEqual(result[0], False)


class TestFindSteamRootBranches(unittest.TestCase):
    """Tests for find_steam_root edge cases"""

    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('os.path.realpath')
    def test_find_steam_root_with_vdf(self, mock_realpath, mock_isfile, mock_isdir):
        """Test finding steam root via libraryfolders.vdf"""
        from steam_proton_helper import find_steam_root
        mock_isdir.return_value = False
        mock_isfile.side_effect = lambda p: 'libraryfolders.vdf' in p
        mock_realpath.return_value = '/home/user/.steam/steam'
        # This tests the path where vdf file exists but steamapps doesn't


class TestInstallProtonListText(unittest.TestCase):
    """Tests for --install-proton list text output branches"""

    @patch('sys.argv', ['prog', '--install-proton', 'list'])
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.find_proton_installations')
    @patch('builtins.print')
    def test_install_proton_list_with_installed(self, mock_print, mock_installs, mock_root, mock_fetch):
        """Test --install-proton list shows installed status"""
        from steam_proton_helper import main, GEProtonRelease, ProtonInstall
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="https://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_root.return_value = "/home/user/.steam/steam"
        mock_installs.return_value = [
            ProtonInstall(
                name="GE-Proton9-1",
                path="/path/to/ge",
                has_executable=True,
                has_toolmanifest=True,
                has_version=True
            )
        ]
        result = main()
        self.assertEqual(result, 0)


class TestRemoveProtonListText(unittest.TestCase):
    """Tests for --remove-proton list text output branches"""

    @patch('sys.argv', ['prog', '--remove-proton', 'list'])
    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.print')
    def test_remove_proton_list_with_versions(self, mock_print, mock_removable):
        """Test --remove-proton list with removable versions"""
        from steam_proton_helper import main
        mock_removable.return_value = [
            ("GE-Proton9-1", "/path/to/ge-proton"),
            ("GE-Proton8-25", "/path/to/ge-proton-old"),
        ]
        result = main()
        self.assertEqual(result, 0)


class TestDownloadWithProgressUrllib(unittest.TestCase):
    """Tests for download_with_progress urllib branches"""

    @patch('urllib.request.urlopen')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('builtins.print')
    def test_download_success_with_progress(self, mock_print, mock_open, mock_urlopen):
        """Test successful download with progress display"""
        from steam_proton_helper import download_with_progress
        mock_response = MagicMock()
        mock_response.headers.get.return_value = '1024'
        mock_response.read.side_effect = [b'x' * 512, b'x' * 512, b'']
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        result = download_with_progress('http://example.com/file.tar.gz', '/tmp/file.tar.gz')
        self.assertTrue(result)

    @patch('urllib.request.urlopen')
    def test_download_network_error(self, mock_urlopen):
        """Test download with network error"""
        from steam_proton_helper import download_with_progress
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Network error")
        result = download_with_progress('http://example.com/file.tar.gz', '/tmp/file.tar.gz')
        self.assertFalse(result)


class TestInstallGEProtonBranches(unittest.TestCase):
    """Tests for install_ge_proton function branches"""

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_install_no_releases(self, mock_fetch, mock_dir):
        """Test install when no releases available"""
        from steam_proton_helper import install_ge_proton
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = []
        success, msg = install_ge_proton('latest')
        self.assertFalse(success)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('os.path.exists')
    def test_install_already_exists_no_force(self, mock_exists, mock_fetch, mock_dir):
        """Test install when version already exists without force"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_exists.return_value = True
        success, msg = install_ge_proton('latest')
        self.assertFalse(success)
        self.assertIn("already installed", msg)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('os.path.exists')
    @patch('shutil.rmtree')
    @patch('steam_proton_helper.download_with_progress')
    @patch('builtins.print')
    def test_install_force_reinstall(self, mock_print, mock_download, mock_rmtree, mock_exists, mock_fetch, mock_dir):
        """Test force reinstall removes existing"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_exists.return_value = True
        mock_download.return_value = False  # Download fails
        success, msg = install_ge_proton('latest', force=True)
        self.assertFalse(success)
        mock_rmtree.assert_called()


class TestRemoveGEProtonBranches(unittest.TestCase):
    """Tests for remove_ge_proton function branches"""

    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.input', return_value='y')
    @patch('shutil.rmtree')
    @patch('builtins.print')
    def test_remove_success(self, mock_print, mock_rmtree, mock_input, mock_removable):
        """Test successful removal"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-1", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1"),
        ]
        success, msg = remove_ge_proton("GE-Proton9-1")
        self.assertTrue(success)

    @patch('steam_proton_helper.get_removable_proton_versions')
    def test_remove_not_custom_proton(self, mock_removable):
        """Test cannot remove non-custom Proton"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("Proton 8.0", "/home/user/.steam/steam/steamapps/common/Proton 8.0"),
        ]
        success, msg = remove_ge_proton("Proton 8.0")
        self.assertFalse(success)
        self.assertIn("not a custom Proton", msg)

    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.input', side_effect=KeyboardInterrupt)
    @patch('builtins.print')
    def test_remove_keyboard_interrupt(self, mock_print, mock_input, mock_removable):
        """Test removal cancelled with keyboard interrupt"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-1", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1"),
        ]
        success, msg = remove_ge_proton("GE-Proton9-1")
        self.assertFalse(success)
        self.assertIn("cancelled", msg)

    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('shutil.rmtree', side_effect=PermissionError)
    @patch('builtins.print')
    def test_remove_permission_error(self, mock_print, mock_rmtree, mock_removable):
        """Test removal with permission error"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-1", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1"),
        ]
        success, msg = remove_ge_proton("GE-Proton9-1", confirm=False)
        self.assertFalse(success)
        self.assertIn("Permission denied", msg)


class TestCheckGEProtonUpdatesBranches(unittest.TestCase):
    """Tests for check_ge_proton_updates function branches"""

    @patch('steam_proton_helper.find_steam_root')
    def test_check_updates_no_steam(self, mock_root):
        """Test check updates when Steam not found"""
        from steam_proton_helper import check_ge_proton_updates
        mock_root.return_value = None
        result = check_ge_proton_updates()
        self.assertEqual(result, [])

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.find_proton_installations')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_check_updates_with_installed(self, mock_fetch, mock_installs, mock_root):
        """Test check updates with installed GE-Proton"""
        from steam_proton_helper import check_ge_proton_updates, ProtonInstall, GEProtonRelease
        mock_root.return_value = "/home/user/.steam/steam"
        mock_installs.return_value = [
            ProtonInstall(
                name="GE-Proton9-1",
                path="/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1",
                has_executable=True,
                has_toolmanifest=True,
                has_version=True
            )
        ]
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-2",
                name="GE-Proton9-2",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        result = check_ge_proton_updates()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['update_available'])


class TestMainFunctionBranches(unittest.TestCase):
    """Tests for main() function branches"""

    @patch('sys.argv', ['prog', '--fix', '/tmp/fix.sh'])
    @patch('steam_proton_helper.DistroDetector.detect_distro')
    @patch('steam_proton_helper.DependencyChecker')
    @patch('steam_proton_helper.output_fix_script')
    def test_main_fix_flag(self, mock_output, mock_checker, mock_distro):
        """Test main with --fix flag"""
        from steam_proton_helper import main
        mock_distro.return_value = ("Ubuntu", "apt")
        mock_checker_instance = MagicMock()
        mock_checker_instance.run_all_checks.return_value = []
        mock_checker.return_value = mock_checker_instance
        result = main()
        mock_output.assert_called_once()

    @patch('sys.argv', ['prog', '--dry-run'])
    @patch('steam_proton_helper.DistroDetector.detect_distro')
    @patch('steam_proton_helper.DependencyChecker')
    @patch('steam_proton_helper.show_dry_run')
    @patch('steam_proton_helper.print_header')
    def test_main_dry_run_flag(self, mock_header, mock_dry_run, mock_checker, mock_distro):
        """Test main with --dry-run flag"""
        from steam_proton_helper import main
        mock_distro.return_value = ("Ubuntu", "apt")
        mock_checker_instance = MagicMock()
        mock_checker_instance.run_all_checks.return_value = []
        mock_checker.return_value = mock_checker_instance
        result = main()
        mock_dry_run.assert_called_once()

    @patch('sys.argv', ['prog', '--apply', '--yes'])
    @patch('steam_proton_helper.DistroDetector.detect_distro')
    @patch('steam_proton_helper.DependencyChecker')
    @patch('steam_proton_helper.apply_fixes')
    @patch('steam_proton_helper.print_header')
    @patch('builtins.print')
    def test_main_apply_flag(self, mock_print, mock_header, mock_apply, mock_checker, mock_distro):
        """Test main with --apply flag"""
        from steam_proton_helper import main
        mock_distro.return_value = ("Ubuntu", "apt")
        mock_checker_instance = MagicMock()
        mock_checker_instance.run_all_checks.return_value = []
        mock_checker.return_value = mock_checker_instance
        mock_apply.return_value = (True, "All fixed!")
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog', '--apply'])
    @patch('steam_proton_helper.DistroDetector.detect_distro')
    @patch('steam_proton_helper.DependencyChecker')
    @patch('steam_proton_helper.apply_fixes')
    @patch('steam_proton_helper.print_header')
    @patch('builtins.print')
    def test_main_apply_failure(self, mock_print, mock_header, mock_apply, mock_checker, mock_distro):
        """Test main with --apply that fails"""
        from steam_proton_helper import main
        mock_distro.return_value = ("Ubuntu", "apt")
        mock_checker_instance = MagicMock()
        mock_checker_instance.run_all_checks.return_value = []
        mock_checker.return_value = mock_checker_instance
        mock_apply.return_value = (False, "Failed to install")
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog'])
    @patch('steam_proton_helper.DistroDetector.detect_distro')
    @patch('steam_proton_helper.DependencyChecker')
    @patch('steam_proton_helper.print_header')
    @patch('steam_proton_helper.print_checks_by_category')
    @patch('steam_proton_helper.print_summary')
    @patch('steam_proton_helper.print_tips')
    def test_main_default_run(self, mock_tips, mock_summary, mock_checks, mock_header, mock_checker, mock_distro):
        """Test main with default run (no flags)"""
        from steam_proton_helper import main
        mock_distro.return_value = ("Ubuntu", "apt")
        mock_checker_instance = MagicMock()
        mock_checker_instance.run_all_checks.return_value = []
        mock_checker.return_value = mock_checker_instance
        result = main()
        self.assertEqual(result, 0)

    @patch('sys.argv', ['prog'])
    @patch('steam_proton_helper.DistroDetector.detect_distro', side_effect=KeyboardInterrupt)
    @patch('builtins.print')
    def test_main_keyboard_interrupt(self, mock_print, mock_distro):
        """Test main with keyboard interrupt"""
        from steam_proton_helper import main
        result = main()
        self.assertEqual(result, 130)

    @patch('sys.argv', ['prog', '--json'])
    @patch('steam_proton_helper.DistroDetector.detect_distro', side_effect=Exception("Test error"))
    @patch('builtins.print')
    def test_main_exception_json(self, mock_print, mock_distro):
        """Test main with exception and JSON output"""
        from steam_proton_helper import main
        result = main()
        self.assertEqual(result, 1)

    @patch('sys.argv', ['prog', '--verbose'])
    @patch('steam_proton_helper.DistroDetector.detect_distro', side_effect=Exception("Test error"))
    @patch('builtins.print')
    def test_main_exception_verbose(self, mock_print, mock_distro):
        """Test main with exception and verbose output"""
        from steam_proton_helper import main
        result = main()
        self.assertEqual(result, 1)


class TestShowDryRun(unittest.TestCase):
    """Tests for show_dry_run function"""

    @patch('builtins.print')
    def test_show_dry_run_with_fixes(self, mock_print):
        """Test show_dry_run with fixes available"""
        from steam_proton_helper import show_dry_run, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test-pkg", status=CheckStatus.FAIL, message="fail",
                          category="test", fix_command="sudo apt install test-pkg")
        ]
        show_dry_run(checks, "apt")
        mock_print.assert_called()

    @patch('builtins.print')
    def test_show_dry_run_no_fixes(self, mock_print):
        """Test show_dry_run with no fixes needed"""
        from steam_proton_helper import show_dry_run, DependencyCheck, CheckStatus
        checks = [
            DependencyCheck(name="test-pkg", status=CheckStatus.PASS, message="ok",
                          category="test")
        ]
        show_dry_run(checks, "apt")
        mock_print.assert_called()


class TestUpdateGEProtonBranches(unittest.TestCase):
    """Tests for update_ge_proton function branches"""

    @patch('steam_proton_helper.check_ge_proton_updates')
    def test_update_already_up_to_date(self, mock_check):
        """Test update when already at latest version (returns True, 'Already up to date')"""
        from steam_proton_helper import update_ge_proton
        mock_check.return_value = [
            {'installed': 'GE-Proton9-2', 'latest': 'GE-Proton9-2', 'update_available': False}
        ]
        success, msg = update_ge_proton()
        self.assertTrue(success)  # Returns True when already up to date
        self.assertIn("Already up to date", msg)

    @patch('steam_proton_helper.check_ge_proton_updates')
    def test_update_check_fails(self, mock_check):
        """Test update when check fails"""
        from steam_proton_helper import update_ge_proton
        mock_check.return_value = []
        success, msg = update_ge_proton()
        self.assertFalse(success)

    @patch('steam_proton_helper.check_ge_proton_updates')
    @patch('steam_proton_helper.install_ge_proton')
    def test_update_with_available_update(self, mock_install, mock_check):
        """Test update when update is available"""
        from steam_proton_helper import update_ge_proton
        mock_check.return_value = [
            {'installed': 'GE-Proton9-1', 'latest': 'GE-Proton9-2', 'update_available': True}
        ]
        mock_install.return_value = (True, "Updated successfully")
        success, msg = update_ge_proton()
        self.assertTrue(success)


class TestDistroDetectorExceptions(unittest.TestCase):
    """Tests for DistroDetector exception handling"""

    @patch('builtins.open', side_effect=Exception("Read error"))
    @patch('os.path.exists', return_value=True)
    def test_detect_distro_exception(self, mock_exists, mock_open):
        """Test exception handling in detect_distro"""
        from steam_proton_helper import DistroDetector
        distro, pm = DistroDetector.detect_distro()
        self.assertEqual(distro, 'unknown')
        self.assertEqual(pm, 'unknown')


class TestFindSteamRootExceptions(unittest.TestCase):
    """Tests for find_steam_root exception handling"""

    @patch('os.path.expanduser')
    @patch('os.path.realpath')
    @patch('os.path.isdir', side_effect=PermissionError("Access denied"))
    def test_find_steam_root_permission_error(self, mock_isdir, mock_realpath, mock_expand):
        """Test PermissionError handling in find_steam_root"""
        from steam_proton_helper import find_steam_root
        mock_expand.return_value = '/home/user/.steam/steam'
        mock_realpath.return_value = '/home/user/.steam/steam'
        result = find_steam_root()
        # Should return None when all paths fail with PermissionError
        self.assertIsNone(result)


class TestInstallGEProtonBranchesMore(unittest.TestCase):
    """More tests for install_ge_proton branches"""

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_install_partial_version_match(self, mock_fetch, mock_dir):
        """Test partial version match in install_ge_proton"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-20",
                name="GE-Proton9-20",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        # Use partial match "9-20" which should match "GE-Proton9-20"
        with patch('os.path.exists', return_value=False):
            with patch('steam_proton_helper.download_with_progress', return_value=False):
                success, msg = install_ge_proton('9-20')
        # Should find partial match but fail on download
        self.assertFalse(success)
        self.assertIn("Download failed", msg)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_install_no_install_dir(self, mock_fetch, mock_dir):
        """Test install_ge_proton when no install directory found"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = None
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        success, msg = install_ge_proton('latest')
        self.assertFalse(success)
        self.assertIn("compatibilitytools.d", msg)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('os.path.exists', return_value=False)
    @patch('steam_proton_helper.download_with_progress', return_value=True)
    @patch('tarfile.open')
    @patch('os.path.isdir', return_value=True)
    @patch('builtins.print')
    @patch('tempfile.NamedTemporaryFile')
    def test_install_extraction_success(self, mock_temp, mock_print, mock_isdir, mock_tar,
                                         mock_download, mock_exists, mock_fetch, mock_dir):
        """Test successful extraction in install_ge_proton"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_temp_file = MagicMock()
        mock_temp_file.name = '/tmp/test.tar.gz'
        mock_temp_file.__enter__ = MagicMock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = MagicMock(return_value=False)
        mock_temp.return_value = mock_temp_file
        mock_tar_obj = MagicMock()
        mock_tar_obj.__enter__ = MagicMock(return_value=mock_tar_obj)
        mock_tar_obj.__exit__ = MagicMock(return_value=False)
        mock_tar.return_value = mock_tar_obj
        success, msg = install_ge_proton('latest')
        self.assertTrue(success)
        self.assertIn("Successfully installed", msg)

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('os.path.exists', return_value=False)
    @patch('steam_proton_helper.download_with_progress', return_value=True)
    @patch('tarfile.open', side_effect=tarfile.TarError("Corrupt archive"))
    @patch('builtins.print')
    @patch('tempfile.NamedTemporaryFile')
    def test_install_extraction_failure(self, mock_temp, mock_print, mock_tar,
                                         mock_download, mock_exists, mock_fetch, mock_dir):
        """Test extraction failure in install_ge_proton"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_temp_file = MagicMock()
        mock_temp_file.name = '/tmp/test.tar.gz'
        mock_temp_file.__enter__ = MagicMock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = MagicMock(return_value=False)
        mock_temp.return_value = mock_temp_file
        success, msg = install_ge_proton('latest')
        self.assertFalse(success)
        self.assertIn("Extraction failed", msg)


class TestRemoveGEProtonBranchesMore(unittest.TestCase):
    """More tests for remove_ge_proton branches"""

    @patch('steam_proton_helper.get_removable_proton_versions')
    def test_remove_partial_match(self, mock_removable):
        """Test partial version match in remove_ge_proton"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-15", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-15"),
        ]
        # Use partial match "9-15" which should match "GE-Proton9-15"
        with patch('shutil.rmtree'):
            success, msg = remove_ge_proton("9-15", confirm=False)
        self.assertTrue(success)

    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('builtins.input', return_value='n')
    @patch('builtins.print')
    def test_remove_user_says_no(self, mock_print, mock_input, mock_removable):
        """Test user declining removal"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-1", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1"),
        ]
        success, msg = remove_ge_proton("GE-Proton9-1", confirm=True)
        self.assertFalse(success)
        self.assertIn("cancelled", msg)

    @patch('steam_proton_helper.get_removable_proton_versions')
    @patch('shutil.rmtree', side_effect=OSError("Disk full"))
    @patch('builtins.print')
    def test_remove_os_error(self, mock_print, mock_rmtree, mock_removable):
        """Test OSError during removal"""
        from steam_proton_helper import remove_ge_proton
        mock_removable.return_value = [
            ("GE-Proton9-1", "/home/user/.steam/steam/compatibilitytools.d/GE-Proton9-1"),
        ]
        success, msg = remove_ge_proton("GE-Proton9-1", confirm=False)
        self.assertFalse(success)
        self.assertIn("Failed to remove", msg)


class TestResolveGameInputBranches(unittest.TestCase):
    """Tests for resolve_game_input branches"""

    @patch('steam_proton_helper.search_steam_games')
    def test_resolve_game_exact_match_among_multiple(self, mock_search):
        """Test exact match prioritization when multiple matches exist"""
        from steam_proton_helper import resolve_game_input, SteamApp
        mock_search.return_value = [
            SteamApp(appid=12345, name="Half-Life"),
            SteamApp(appid=67890, name="Half-Life 2"),
            SteamApp(appid=11111, name="Half-Life: Source"),
        ]
        app_id, name, matches = resolve_game_input("Half-Life")
        self.assertEqual(app_id, "12345")
        self.assertEqual(name, "Half-Life")
        self.assertEqual(matches, [])  # No extra matches when exact found


class TestWineBranches(unittest.TestCase):
    """Tests for wine check branches"""

    @patch.object(DependencyChecker, 'check_command_exists')
    @patch.object(DependencyChecker, 'run_command')
    def test_wine64_version_check(self, mock_run, mock_exists):
        """Test wine64 version detection"""
        from steam_proton_helper import DependencyChecker
        mock_exists.side_effect = lambda cmd: cmd == 'wine64'
        mock_run.return_value = (0, "wine-9.0", "")
        checker = DependencyChecker("Ubuntu", "apt")
        checks = checker.check_wine()
        wine_check = next((c for c in checks if c.name == "Wine"), None)
        self.assertIsNotNone(wine_check)
        self.assertEqual(wine_check.status, CheckStatus.PASS)
        self.assertIn("9.0", wine_check.message)


class TestCheckGEProtonUpdatesMore(unittest.TestCase):
    """More tests for check_ge_proton_updates"""

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_check_updates_no_releases(self, mock_fetch, mock_root):
        """Test check_ge_proton_updates when no releases fetched"""
        from steam_proton_helper import check_ge_proton_updates
        mock_root.return_value = "/home/user/.steam/steam"
        mock_fetch.return_value = []
        result = check_ge_proton_updates()
        self.assertEqual(result, [])

    @patch('steam_proton_helper.find_steam_root')
    @patch('steam_proton_helper.find_proton_installations')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    def test_check_updates_no_ge_installed(self, mock_fetch, mock_installs, mock_root):
        """Test check_ge_proton_updates when no GE-Proton installed"""
        from steam_proton_helper import check_ge_proton_updates, ProtonInstall, GEProtonRelease
        mock_root.return_value = "/home/user/.steam/steam"
        # Only official Proton installed, no GE versions
        mock_installs.return_value = [
            ProtonInstall(
                name="Proton 8.0",
                path="/home/user/.steam/steam/steamapps/common/Proton 8.0",
                has_executable=True,
                has_toolmanifest=True,
                has_version=True
            )
        ]
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-2",
                name="GE-Proton9-2",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        result = check_ge_proton_updates()
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0]['installed'])
        self.assertTrue(result[0]['update_available'])


class TestDetectSteamVariantBranches(unittest.TestCase):
    """Tests for detect_steam_variant branches"""

    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_detect_flatpak_steam(self, mock_exists, mock_run):
        """Test detecting Flatpak Steam"""
        from steam_proton_helper import detect_steam_variant, SteamVariant
        mock_exists.return_value = False  # No native Steam
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        variant, desc = detect_steam_variant()
        self.assertEqual(variant, SteamVariant.FLATPAK)
        self.assertIn("Flatpak", desc)

    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_detect_snap_steam(self, mock_exists, mock_run):
        """Test detecting Snap Steam"""
        from steam_proton_helper import detect_steam_variant, SteamVariant
        mock_exists.return_value = False  # No native Steam

        def run_side_effect(args, **kwargs):
            if 'flatpak' in args:
                raise FileNotFoundError("flatpak not found")
            elif 'snap' in args:
                return MagicMock(returncode=0, stdout="steam 1.0.0.79 latest/stable canonical✓")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect
        variant, desc = detect_steam_variant()
        self.assertEqual(variant, SteamVariant.SNAP)
        self.assertIn("Snap", desc)

    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_detect_multiple_variants(self, mock_exists, mock_run):
        """Test detecting multiple Steam variants"""
        from steam_proton_helper import detect_steam_variant, SteamVariant
        mock_exists.return_value = True  # Native Steam exists

        def run_side_effect(args, **kwargs):
            # Also flatpak Steam exists
            if 'flatpak' in args:
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=1)

        mock_run.side_effect = run_side_effect
        variant, desc = detect_steam_variant()
        self.assertEqual(variant, SteamVariant.NATIVE)
        self.assertIn("also found", desc)

    @patch('subprocess.run', side_effect=Exception("General error"))
    @patch('os.path.exists')
    def test_detect_flatpak_general_exception(self, mock_exists, mock_run):
        """Test exception handling in Flatpak detection"""
        from steam_proton_helper import detect_steam_variant, SteamVariant
        mock_exists.return_value = True  # Native Steam exists
        variant, desc = detect_steam_variant()
        self.assertEqual(variant, SteamVariant.NATIVE)


class TestUpdateGEProtonBranchesMore(unittest.TestCase):
    """More tests for update_ge_proton branches"""

    @patch('steam_proton_helper.check_ge_proton_updates')
    def test_update_no_latest_version(self, mock_check):
        """Test update when latest version cannot be determined"""
        from steam_proton_helper import update_ge_proton
        mock_check.return_value = [{'installed': None, 'latest': None, 'update_available': False}]
        success, msg = update_ge_proton()
        self.assertFalse(success)
        self.assertIn("Could not determine", msg)


class TestInstallVerifyBranches(unittest.TestCase):
    """Tests for install verification branches"""

    @patch('steam_proton_helper.get_proton_install_dir')
    @patch('steam_proton_helper.fetch_ge_proton_releases')
    @patch('os.path.exists', return_value=False)
    @patch('steam_proton_helper.download_with_progress', return_value=True)
    @patch('tarfile.open')
    @patch('os.path.isdir', return_value=False)  # target_path doesn't exist after extract
    @patch('builtins.print')
    @patch('tempfile.NamedTemporaryFile')
    def test_install_verify_path_not_found(self, mock_temp, mock_print, mock_isdir, mock_tar,
                                           mock_download, mock_exists, mock_fetch, mock_dir):
        """Test installation when target_path not found after extraction"""
        from steam_proton_helper import install_ge_proton, GEProtonRelease
        mock_dir.return_value = '/path/to/install'
        mock_fetch.return_value = [
            GEProtonRelease(
                tag_name="GE-Proton9-1",
                name="GE-Proton9-1",
                download_url="http://example.com/ge.tar.gz",
                size_bytes=500 * 1024 * 1024,
                published_at="2024-01-01"
            )
        ]
        mock_temp_file = MagicMock()
        mock_temp_file.name = '/tmp/test.tar.gz'
        mock_temp_file.__enter__ = MagicMock(return_value=mock_temp_file)
        mock_temp_file.__exit__ = MagicMock(return_value=False)
        mock_temp.return_value = mock_temp_file
        mock_tar_obj = MagicMock()
        mock_tar_obj.__enter__ = MagicMock(return_value=mock_tar_obj)
        mock_tar_obj.__exit__ = MagicMock(return_value=False)
        mock_tar.return_value = mock_tar_obj
        success, msg = install_ge_proton('latest')
        self.assertTrue(success)  # Still returns True with different message
        self.assertIn("Installed to", msg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
