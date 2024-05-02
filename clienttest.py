import unittest
import time
from unittest.mock import patch, MagicMock, Mock
from client import connect_to_server, parse_log_entries, createUserHelper, blockUserHelper, delete_user_helper, user_handler, receive_photos_continuously
import threading




class TestServerConnection(unittest.TestCase):


    @patch('client.json.dumps')
    def test_create_user_success(self, json_dumps_mock):
        # Mocks and setup
        server_socket_mock = Mock()
        role = "admin"
        json_dumps_mock.return_value = '{"username": "test_username", "password": "Create User"}'

        # Patching
        with patch('client.frontend_dashboard.get_password', return_value="test_password"):
            with patch('client.frontend_dashboard.display_message') as display_message_mock:
                createUserHelper("test_username", "Create User", server_socket_mock, role)


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
        Time: 23/Apr/2024:23:13:03 , IP address: 127.0.0.1, Username: superadmin, Status: Success, Action: Log In, Done By: superadmin, Role: Superadmin
        Time: 23/Apr/2024:23:13:22 , IP address: 127.0.0.1, Username: superadmin, Status: Success, Action: Log Out, Done By: superadmin, Role: Superadmin
        Time: 23/Apr/2024:23:14:02 , IP address: 127.0.0.1, Username: beth, Status: Failed, Action: Log In, Done By: nithya, Role: User
        Time: 23/Apr/2024:23:14:09 , IP address: 127.0.0.1, Username: admin2, Status: Success, Action: Log In, Done By: admin2, Role: Admin
        Time: 23/Apr/2024:23:14:26 , IP address: 127.0.0.1, Username: admin2, Status: Success, Action: Log Out, Done By: admin2, Role: Admin
        """

        # Expected structure after parsing
        expected = [
            {'Time': '23/Apr/2024:23:13:03', 'IP Address': '127.0.0.1', 'Username': 'superadmin', 'Status': 'Success', 'Action': 'Log In', 'Done By': 'superadmin', 'Role': 'Superadmin'},
            {'Time': '23/Apr/2024:23:13:22', 'IP Address': '127.0.0.1', 'Username': 'superadmin', 'Status': 'Success', 'Action': 'Log Out', 'Done By': 'superadmin', 'Role': 'Superadmin'},
            {'Time': '23/Apr/2024:23:14:02', 'IP Address': '127.0.0.1', 'Username': 'beth', 'Status': 'Failed', 'Action': 'Log In', 'Done By': 'nithya', 'Role': 'User'},
            {'Time': '23/Apr/2024:23:14:09', 'IP Address': '127.0.0.1', 'Username': 'admin2', 'Status': 'Success', 'Action': 'Log In', 'Done By': 'admin2', 'Role': 'Admin'},
            {'Time': '23/Apr/2024:23:14:26', 'IP Address': '127.0.0.1', 'Username': 'admin2', 'Status': 'Success', 'Action': 'Log Out', 'Done By': 'admin2', 'Role': 'Admin'}
        ]

        # Act: Parse the log data
        result = parse_log_entries(log_data)

        # Assert: Verify that the parsed data matches the expected result
        self.assertEqual(result, expected)


class TestBlockUserHelper(unittest.TestCase):
    def test_permission_denied(self):
        status = 0
        with unittest.mock.patch('client.frontend_dashboard.display_message') as display_message_mock:
            blockUserHelper(status)
            display_message_mock.assert_called_with("Permission denied: No authorization to block this account. Returning to menu...")
    
    def test_successfully_blocked(self):
        status = 1
        with unittest.mock.patch('client.frontend_dashboard.display_message') as display_message_mock:
            blockUserHelper(status)
            display_message_mock.assert_called_with("Successfully blocked this user. Returning to menu...")

    def test_user_does_not_exist(self):
        status = 2
        with unittest.mock.patch('client.frontend_dashboard.display_message') as display_message_mock:
            blockUserHelper(status)
            display_message_mock.assert_called_with("User does not exist. Returning to menu...")

class TestDeleteUserHelper(unittest.TestCase):

    @patch('client.frontend_dashboard.display_message')
    def test_permission_denied(self, display_message_mock):
        server_socket_mock = Mock()
        server_socket_mock.recv.return_value = "Denied".encode()
        delete_user_helper("test_username", "Delete", "target_user", server_socket_mock)
        display_message_mock.assert_called_with("Permission denied: No authorization to delete this account. Returning to menu...")

    @patch('client.frontend_dashboard.display_message')
    def test_success(self, display_message_mock):
        server_socket_mock = Mock()
        server_socket_mock.recv.return_value = "Success".encode()
        delete_user_helper("test_username", "Delete", "target_user", server_socket_mock)
        display_message_mock.assert_called_with("User removed. Returning to menu...")

    @patch('client.frontend_dashboard.display_message')
    def test_user_not_found(self, display_message_mock):
        server_socket_mock = Mock()
        server_socket_mock.recv.return_value = "User not found".encode()
        delete_user_helper("test_username", "Delete", "target_user", server_socket_mock)
        display_message_mock.assert_called_with("User does not exist. Returning to menu...")




if __name__ == '__main__':
    unittest.main()
