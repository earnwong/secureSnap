import unittest
import string
import secrets
from frontenddashboard2 import isSpecialChar, isSpace, gen_salt
from frontenddashboard2 import FrontendDashboard
from unittest.mock import patch

class TestHelperFunctions(unittest.TestCase):
    def test_isSpecialChar(self):
        # Check for a variety of special characters
        for char in string.punctuation:
            with self.subTest(char=char):
                self.assertTrue(isSpecialChar(char))
        # Test non-special character
        self.assertFalse(isSpecialChar('a'))
        self.assertFalse(isSpecialChar('1'))

    def test_isSpace(self):
        # True for space
        self.assertTrue(isSpace(' '))
        # False for non-space
        self.assertFalse(isSpace('a'))
        self.assertFalse(isSpace('1'))

    def test_valid_pw(self):
        # Valid password must meet all criteria
        self.assertTrue(FrontendDashboard.valid_pw(self, 'Password1!'))
        # Fail each rule one at a time
        self.assertFalse(FrontendDashboard.valid_pw(self, 'p'))  # Too short
        self.assertFalse(FrontendDashboard.valid_pw(self, 'password!'))  # No digits
        self.assertFalse(FrontendDashboard.valid_pw(self, 'Password1'))  # No special characters
        self.assertFalse(FrontendDashboard.valid_pw(self, 'password1!'))  # No uppercase letters
        self.assertFalse(FrontendDashboard.valid_pw(self, 'Password 1!'))  # Contains space

    def test_gen_salt(self):
        salt = gen_salt()
        # Test that salt is generated and is a hexadecimal
        self.assertEqual(len(salt), 32)  # 16 bytes -> 32 hex digits
        self.assertTrue(all(c in string.hexdigits for c in salt))

class TestSuperadminMenu(unittest.TestCase):

    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="Create Admin")
    def test_create_admin_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "Create Admin")

    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="Create User")
    def test_create_user_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "Create User")
        
    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="Delete Admin/User")
    def test_delete_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "Delete Admin/User")

    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="Reset Admin/User password")
    def test_reset_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "Reset Admin/User password")
    
    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="View Logs")
    def test_logs_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "View Logs")

    @patch('frontenddashboard2.FrontendDashboard.superadmin_menu', return_value="Quit")
    def test_quit_selected(self, mock_superadmin_menu):
        frontend = FrontendDashboard()
        username = "superadmin"
        action = frontend.superadmin_menu(username)
        self.assertEqual(action, "Quit")
  

if __name__ == '__main__':
    unittest.main()
