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
import sys
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
        import steam_proton_helper
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
