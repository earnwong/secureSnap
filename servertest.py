from unittest.mock import patch, MagicMock, Mock
import unittest
from server import create_user_helper, user_handler, client_handler, log_action, main
import json
import sys, ssl, socket

class TestServer(unittest.TestCase):
    def setUp(self):
        self.connfd = MagicMock()

    @patch('server.backenddashboard')
    def test_create_user_helper(self, mock_backend):
        mock_backend.check_user_taken.return_value = False
        self.connfd.recv.return_value = b'{"username": "user2", "password": "pass2"}'
        result = create_user_helper(self.connfd, "user2")
        self.assertEqual(result, ("user2", "pass2"))

    @patch('server.backenddashboard')
    def test_user_handler(self, mock_backenddashboard):
        # Set up mock data for testing
        username = 'test_user'
        password = 'block'
        mock_backenddashboard.check_blocked_user.return_value = 0  # Assuming the user is not blocked

        # Construct the authentication info JSON
        auth_info = {
            'username': username,
            'password': password
        }
        # Encode JSON to bytes
        auth_data = json.dumps(auth_info).encode('utf-8')

        self.connfd.recv.side_effect = [auth_data, b'']

        # Mock the receive method of the connection socket
        #self.connfd.recv.return_value = auth_data

        # Call the function being tested
        user_handler(self.connfd, username)



    def test_successful_superadmin_login(self):
        # Simulate a successful superadmin login scenario
        with patch('server.backenddashboard.auth_login') as mock_auth_login:
            mock_auth_login.return_value = ("0",)
            self.connfd.recv.side_effect = [
                b'{"username": "admin", "password": "adminpass", "action": "Login"}',
                b'{"username": "admin", "password": "adminpass", "action": "END_SESSION_SUPER_ADMIN"}'
            ]
            client_handler(self.connfd)

    def test_successful_admin_login(self):
        # Simulate a successful admin login scenario
        with patch('server.backenddashboard.auth_login') as mock_auth_login:
            mock_auth_login.return_value = ("1",)
            self.connfd.recv.side_effect = [
                b'{"username": "admin", "password": "adminpass", "action": "Login"}',
                b'{"username": "admin", "password": "adminpass", "action": "END_SESSION_ADMIN"}'
            ]
            client_handler(self.connfd)

    def test_successful_user_login(self):
        # Simulate a successful user login scenario
        with patch('server.backenddashboard.auth_login') as mock_auth_login:
            mock_auth_login.return_value = ("2",)
            self.connfd.recv.side_effect = [
                b'{"username": "user", "password": "userpass", "action": "Login"}',
                b'{"username": "user", "password": "userpass", "action": "END_SESSION"}'
            ]
            client_handler(self.connfd)
            
    

    @patch('server.backenddashboard')
    def test_client_handler_2(self, mock_backenddashboard):
        username = 'test_user'
        password = 'test_password'
        mock_backenddashboard.auth_login.return_value = "2"  # Assuming authentication is successful for a regular user

        # Construct the authentication info JSON
        auth_info = {
            'username': username,
            'password': password
        }
        # auth_info1 = {
        #     'username': 'user2',
        #     'password': 'Logs'
        # }
        # Encode JSON to bytes
        auth_data = json.dumps(auth_info).encode('utf-8')
        #auth_data2 = json.dumps(auth_info1).encode('utf-8')

        # Set side_effect for recv to return data once and then return an empty byte string
        self.connfd.recv.side_effect = [auth_data]

        # Call the function being tested
        client_handler(self.connfd)

    @patch('server.backenddashboard')
    def test_client_handler_0(self, mock_backenddashboard):
        username = 'test_user'
        password = 'test_password'
        mock_backenddashboard.auth_login.return_value = "0"  # Assuming authentication is successful for a regular user

        # Construct the authentication info JSON
        auth_info = {
            'username': username,
            'password': password
        }
        auth_info1 = {
            'username': 'user2',
            'password': 'Create User'
        }
        # Encode JSON to bytes
        auth_data = json.dumps(auth_info).encode('utf-8')
        #auth_data2 = json.dumps(auth_info1).encode('utf-8')

        # Set side_effect for recv to return data once and then return an empty byte string
        self.connfd.recv.side_effect = [auth_data]

        # Call the function being tested
        client_handler(self.connfd)

    @patch('server.backenddashboard')
    def test_client_handler_1(self, mock_backenddashboard):
        username = 'test_user'
        password = 'test_password'
        mock_backenddashboard.auth_login.return_value = "1"  # Assuming authentication is successful for a regular user

        # Construct the authentication info JSON
        auth_info = {
            'username': username,
            'password': password
        }
        auth_info1 = {
            'username': 'user2',
            'password': 'Logs'
        }
        # Encode JSON to bytes
        auth_data = json.dumps(auth_info).encode('utf-8')
        auth_data2 = json.dumps(auth_info1).encode('utf-8')

        # Set side_effect for recv to return data once and then return an empty byte string
        self.connfd.recv.side_effect = [auth_data, auth_data2]

        # Call the function being tested
        client_handler(self.connfd)



    @patch('server.create_user_helper')
    @patch('server.backenddashboard')
    @patch('server.log_action')
    def test_user_operations(self, mock_log_action, mock_backenddashboard, mock_create_user_helper):
        # Set up mock data for testing
        username = 'test_user'
        password = 'test_password'
        action = 'Create User'
        target_user = 'target_user'

        # Mock create_user_helper function to return a valid username and password
        mock_create_user_helper.return_value = ('created_user', 'created_password')

        # Mock backenddashboard functions
        mock_backenddashboard.create_user.side_effect = lambda role, user, pwd: print(f"Mock create_user called with role={role}, user={user}, pwd={pwd}")
        mock_backenddashboard.delete_user.side_effect = lambda deleter, target: print(f"Mock delete_user called with deleter={deleter}, target={target}")
        
        # Construct the authentication info JSON
        auth_info = {
            'username': username,
            'password': password,
            'target_user': target_user
        }
        # Encode JSON to bytes
        auth_data = json.dumps(auth_info).encode('utf-8')

        # Set side_effect for recv to return data once and then return an empty byte string
        self.connfd.recv.side_effect = [auth_data, b'']

        # Call the function being tested
        client_handler(self.connfd)

    @patch('server.json.loads')
    def test_session_termination(self, mock_json_loads):
        # Simulate the end of a session by receiving "END_SESSION" action
        mock_json_loads.return_value = {"username": None, "password": "END_SESSION"}
        user_handler(self.connfd, "test_user")
        # Assert that the session termination message is printed
        self.connfd.sendall.assert_not_called()  # Assuming no response is sent for session termination
        self.assertTrue(self.connfd.close.called)

    @patch('server.json.loads')
    def test_send_logged_in_users(self, mock_json_loads):
        # Simulate the request to send logged-in users list
        mock_json_loads.side_effect = [
            {"username": None, "password": "send"},
            # To exit the loop
            {"username": None, "password": "END_SESSION"}
        ]
        user_handler(self.connfd, "test_user")
        # Assert that the list of logged-in users is sent
        self.assertTrue(self.connfd.sendall.called)

    


    def test_create_admin_action(self):
        # Prepare a mock auth_info with 'Create Admin' action
        auth_info = {
            'username': 'test_admin',
            'password': 'Create Admin'
        }
        # Mock recv method to return encoded auth_info
        self.connfd.recv.return_value = json.dumps(auth_info).encode('utf-8')

        # Call client_handler with mock SSL socket
        client_handler(self.connfd)

        # Add assertions here to check if the expected actions were performed

    def test_delete_action(self):
        # Prepare a mock auth_info with 'Delete' action
        auth_info = {
            'username': 'test_admin',
            'password': 'Delete',
            'target_user': 'user_to_delete'
        }
        # Mock recv method to return encoded auth_info
        self.connfd.recv.return_value = json.dumps(auth_info).encode('utf-8')

        # Call client_handler with mock SSL socket
        client_handler(self.connfd)


  

if __name__ == '__main__':
    unittest.main()

