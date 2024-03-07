import unittest
from unittest.mock import patch, MagicMock
import client  
import socket

class TestClient(unittest.TestCase):

    @patch('client.socket.socket')
    def test_connect_to_server(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        host = 'localhost'
        port = 8047
        username = 'bob'

        sock = client.connect_to_server(host, port, username)

        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.connect.assert_called_with((host, port))
        mock_sock_instance.sendall.assert_called_with(username.encode())
        self.assertEqual(sock, mock_sock_instance)

if __name__ == '__main__':
    unittest.main()



