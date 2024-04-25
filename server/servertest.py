from unittest.mock import patch, MagicMock
import unittest
from server import create_user_helper, client_handler

class TestServer(unittest.TestCase):
    def setUp(self):
        self.connfd = MagicMock()

    @patch('server.backenddashboard')
    def test_create_user_helper(self, mock_backend):
        mock_backend.check_user_taken.return_value = False
        self.connfd.recv.return_value = b'{"username": "user2", "password": "pass2"}'
        result = create_user_helper(self.connfd, "user2")
        self.assertEqual(result, ("user2", "pass2"))

if __name__ == '__main__':
    unittest.main()
