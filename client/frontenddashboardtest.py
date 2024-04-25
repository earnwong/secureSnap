import unittest
import string
import secrets
from frontenddashboard2 import isSpecialChar, isSpace, valid_pw, gen_salt

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
        self.assertTrue(valid_pw('Password1!'))
        # Fail each rule one at a time
        self.assertFalse(valid_pw('p'))  # Too short
        self.assertFalse(valid_pw('password!'))  # No digits
        self.assertFalse(valid_pw('Password1'))  # No special characters
        self.assertFalse(valid_pw('password1!'))  # No uppercase letters
        self.assertFalse(valid_pw('Password 1!'))  # Contains space

    def test_gen_salt(self):
        salt = gen_salt()
        # Test that salt is generated and is a hexadecimal
        self.assertEqual(len(salt), 32)  # 16 bytes -> 32 hex digits
        self.assertTrue(all(c in string.hexdigits for c in salt))

if __name__ == '__main__':
    unittest.main()
