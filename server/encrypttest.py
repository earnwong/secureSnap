import unittest
from unittest.mock import patch, MagicMock
from server.encrypt import EncryptDecrypt, SessionManager

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json
import os

class TestEncryptDecrypt(unittest.TestCase):

    def setUp(self):
        self.encrypt_decrypt = EncryptDecrypt()

    def test_rsa(self):
        user = "test_user"
        self.encrypt_decrypt.generate_rsa_keys(user)
        private_key = self.encrypt_decrypt.load_rsa_private_key(user)
        public_key = self.encrypt_decrypt.load_rsa_public_key(user)

        self.assertIsInstance(private_key, RSA.RsaKey)
        self.assertIsInstance(public_key, RSA.RsaKey)
    
    def test_aes(self):
        data = b"test data"
        aes_key = get_random_bytes(16)  # 16 bytes * 8 = 128 bits
        recipient_user = "samantha"
        encrypted_data = self.encrypt_decrypt.aes_encrypt(data, recipient_user, aes_key)
        decrypted_data = self.encrypt_decrypt.aes_decrypt(encrypted_data, recipient_user)

        self.assertEqual(data, decrypted_data)

class TestSessionManager(unittest.TestCase):

    def setUp(self):
        self.session_manager = SessionManager()

    def test_generate_session_id(self):
        session_id = self.session_manager.generate_session_id()
        self.assertIsInstance(session_id, str)

    def test_generate_aes_key(self):
        aes_key = self.session_manager.generate_aes_key()
        self.assertIsInstance(aes_key, str)
        self.assertEqual(len(b64decode(aes_key)), 32)

    def test_create_session(self):
        username = "bob"
        recipient = "sam"
        session_id = self.session_manager.create_session(username, recipient)
        self.assertIsInstance(session_id, str)

    def test_delete_session(self):
        username = "bob"
        recipient = "sam"
        session_id = self.session_manager.create_session(username, recipient)
        self.session_manager.delete_session(session_id)
        self.assertIsNone(self.session_manager.get_session(session_id))

if __name__ == '__main__':
    unittest.main()