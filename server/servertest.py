import unittest
from unittest.mock import MagicMock, patch
import server.server as server 

class TestServer(unittest.TestCase):

    @patch('server.clients', {'bob': MagicMock(), 'samantha': MagicMock()})
    def test_client_handler_valid_user(self):
        # Mocking the socket connection
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [
            "bob".encode(),  # username
            "END_SESSION".encode()  # simulate ending the session
        ]

        server.client_handler(mock_conn)

        # Check if login response was sent
        mock_conn.sendall.assert_any_call("You have successfully logged in".encode())

        # Ensure the connection is closed after handling
        mock_conn.close.assert_called()

    @patch('server.clients', {'bob': MagicMock(), 'samantha': MagicMock()})
    def test_client_handler_wrong_user(self):
        # Mocking the socket connection
        mock_conn = MagicMock()
        mock_conn.recv.return_value = "unknown_user".encode()  # username not in clients

        server.client_handler(mock_conn)

        # Check if error response was sent
        mock_conn.sendall.assert_called_with("Wrong username".encode())

        # Ensure the connection is closed after handling
        mock_conn.close.assert_called()

# Ensure the file is not executed when being imported
if __name__ == '__main__':
    unittest.main()
