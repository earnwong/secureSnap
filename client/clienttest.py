import unittest
from unittest.mock import patch, MagicMock
from client import connect_to_server, parse_log_entries

class TestServerConnection(unittest.TestCase):
    @patch('client.socket.socket')
    @patch('client.ssl.create_default_context')
    def test_connect_to_server_success(self, mock_ssl_context, mock_socket):
        # Setup
        mock_socket.return_value = MagicMock()
        mock_ssl = MagicMock()
        mock_ssl_context.return_value = mock_ssl
        host = 'localhost'
        port = 8000
        
        # Execute
        result = connect_to_server(host, port)
        
        # Verify
        mock_ssl.wrap_socket.assert_called_once()
        self.assertIsNotNone(result)
    
    def test_parse_log_entries(self):
        # Given log data with multiple entries
        log_data = """
        Time: 23/Apr/2024:23:13:03 , IP address: 127.0.0.1, Username: superadmin, Status: Success, Action: Log In, Role: Superadmin
        Time: 23/Apr/2024:23:13:22 , IP address: 127.0.0.1, Username: superadmin, Status: Success, Action: Log Out, Role: Superadmin
        Time: 23/Apr/2024:23:14:02 , IP address: 127.0.0.1, Username: beth, Status: Failed, Action: Log In, Role: User
        Time: 23/Apr/2024:23:14:09 , IP address: 127.0.0.1, Username: admin2, Status: Success, Action: Log In, Role: Admin
        Time: 23/Apr/2024:23:14:26 , IP address: 127.0.0.1, Username: admin2, Status: Success, Action: Log Out, Role: Admin
        """

        # Expected structure after parsing
        expected = [
            {'Time': '23/Apr/2024:23:13:03', 'IP Address': '127.0.0.1', 'Username': 'superadmin', 'Status': 'Success', 'Action': 'Log In', 'Role': 'Superadmin'},
            {'Time': '23/Apr/2024:23:13:22', 'IP Address': '127.0.0.1', 'Username': 'superadmin', 'Status': 'Success', 'Action': 'Log Out', 'Role': 'Superadmin'},
            {'Time': '23/Apr/2024:23:14:02', 'IP Address': '127.0.0.1', 'Username': 'beth', 'Status': 'Failed', 'Action': 'Log In', 'Role': 'User'},
            {'Time': '23/Apr/2024:23:14:09', 'IP Address': '127.0.0.1', 'Username': 'admin2', 'Status': 'Success', 'Action': 'Log In', 'Role': 'Admin'},
            {'Time': '23/Apr/2024:23:14:26', 'IP Address': '127.0.0.1', 'Username': 'admin2', 'Status': 'Success', 'Action': 'Log Out', 'Role': 'Admin'}
        ]

        # Act: Parse the log data
        result = parse_log_entries(log_data)

        # Assert: Verify that the parsed data matches the expected result
        self.assertEqual(result, expected)
    

if __name__ == '__main__':
    unittest.main()
