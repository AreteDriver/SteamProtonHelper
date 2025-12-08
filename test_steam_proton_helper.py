#!/usr/bin/env python3
"""
Basic tests for Steam Proton Helper
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from steam_proton_helper import (
    CheckStatus, 
    DependencyCheck, 
    DistroDetector,
    DependencyChecker
)


class TestCheckStatus(unittest.TestCase):
    """Test CheckStatus enum"""
    
    def test_status_values(self):
        """Test that status enum has correct values"""
        self.assertEqual(CheckStatus.PASS.value, "✓")
        self.assertEqual(CheckStatus.FAIL.value, "✗")
        self.assertEqual(CheckStatus.WARNING.value, "⚠")
        self.assertEqual(CheckStatus.SKIPPED.value, "○")


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
        self.assertIsNone(check.fix_command)
    
    def test_check_with_fix(self):
        """Test creating a check with fix command"""
        check = DependencyCheck(
            name="Test",
            status=CheckStatus.FAIL,
            message="Test failed",
            fix_command="sudo apt install test"
        )
        self.assertEqual(check.fix_command, "sudo apt install test")


class TestDistroDetector(unittest.TestCase):
    """Test DistroDetector class"""
    
    def test_detect_distro(self):
        """Test distro detection returns valid values"""
        distro, pkg_mgr = DistroDetector.detect_distro()
        
        # Should return strings
        self.assertIsInstance(distro, str)
        self.assertIsInstance(pkg_mgr, str)
        
        # Package manager should be one of the known ones or unknown
        valid_pkg_mgrs = ['apt', 'dnf', 'pacman', 'zypper', 'unknown']
        self.assertIn(pkg_mgr, valid_pkg_mgrs)


class TestDependencyChecker(unittest.TestCase):
    """Test DependencyChecker class"""
    
    def setUp(self):
        """Set up test fixture"""
        self.checker = DependencyChecker('ubuntu', 'apt')
    
    def test_initialization(self):
        """Test checker initialization"""
        self.assertEqual(self.checker.distro, 'ubuntu')
        self.assertEqual(self.checker.package_manager, 'apt')
    
    def test_run_command(self):
        """Test run_command method"""
        code, output = self.checker.run_command(['echo', 'test'])
        self.assertEqual(code, 0)
        self.assertIn('test', output)
    
    def test_check_command_exists(self):
        """Test check_command_exists method"""
        # ls should exist on all systems
        self.assertTrue(self.checker.check_command_exists('ls'))
        
        # This command should not exist
        self.assertFalse(self.checker.check_command_exists('nonexistent_command_xyz'))
    
    def test_check_steam_installed(self):
        """Test Steam check returns valid result"""
        result = self.checker.check_steam_installed()
        
        self.assertIsInstance(result, DependencyCheck)
        self.assertEqual(result.name, "Steam Client")
        self.assertIn(result.status, [CheckStatus.PASS, CheckStatus.FAIL])
    
    def test_check_graphics_drivers(self):
        """Test graphics driver checks"""
        results = self.checker.check_graphics_drivers()
        
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        
        for result in results:
            self.assertIsInstance(result, DependencyCheck)
    
    def test_check_required_libraries(self):
        """Test required libraries check"""
        results = self.checker.check_required_libraries()
        
        self.assertIsInstance(results, list)
        # Should have at least one check
        self.assertGreater(len(results), 0)
    
    def test_check_proton(self):
        """Test Proton check"""
        result = self.checker.check_proton()
        
        self.assertIsInstance(result, DependencyCheck)
        self.assertEqual(result.name, "Proton")
        self.assertIn(result.status, [CheckStatus.PASS, CheckStatus.WARNING])
    
    def test_get_install_command(self):
        """Test install command generation"""
        # Test for apt
        checker_apt = DependencyChecker('ubuntu', 'apt')
        cmd = checker_apt._get_install_command('test-package')
        self.assertIn('apt', cmd)
        self.assertIn('test-package', cmd)
        
        # Test for dnf
        checker_dnf = DependencyChecker('fedora', 'dnf')
        cmd = checker_dnf._get_install_command('test-package')
        self.assertIn('dnf', cmd)
        self.assertIn('test-package', cmd)
        
        # Test for pacman
        checker_pacman = DependencyChecker('arch', 'pacman')
        cmd = checker_pacman._get_install_command('test-package')
        self.assertIn('pacman', cmd)
        self.assertIn('test-package', cmd)
    
    def test_run_all_checks(self):
        """Test running all checks"""
        results = self.checker.run_all_checks()
        
        self.assertIsInstance(results, list)
        # Should have multiple checks
        self.assertGreater(len(results), 3)
        
        # All results should be DependencyCheck instances
        for result in results:
            self.assertIsInstance(result, DependencyCheck)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_workflow(self):
        """Test the full workflow doesn't crash"""
        from steam_proton_helper import SteamProtonHelper
        
        helper = SteamProtonHelper()
        
        # Just verify it initializes correctly
        self.assertIsNotNone(helper.distro)
        self.assertIsNotNone(helper.package_manager)
        self.assertIsNotNone(helper.checker)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
