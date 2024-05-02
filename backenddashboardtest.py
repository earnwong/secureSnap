import unittest
from unittest.mock import patch, MagicMock, mock_open
from backenddashboard import BackendDashboard
import pandas as pd

class TestBackendDashboard(unittest.TestCase):
    def setUp(self):
        self.dashboard = BackendDashboard()

    def test_check_blocked_user(self):
        # Test when user to block exists and user has permission
        user = "admin"
        user_to_block = "user_to_block"
        with patch.object(self.dashboard, 'read_csv_as_df', return_value=pd.DataFrame({"username": [user_to_block]})), \
             patch.object(self.dashboard, 'auth_action', return_value=True):
            self.assertEqual(self.dashboard.check_blocked_user(user, user_to_block), 1)

        # Test when user to block exists but user does not have permission
        with patch.object(self.dashboard, 'read_csv_as_df', return_value=pd.DataFrame({"username": [user_to_block]})), \
             patch.object(self.dashboard, 'auth_action', return_value=False):
            self.assertEqual(self.dashboard.check_blocked_user(user, user_to_block), 0)

        # Test when user to block does not exist
        user_to_block_not_exist = "non_existing_user"
        with patch.object(self.dashboard, 'read_csv_as_df', return_value=pd.DataFrame({"username": [user_to_block]})):
            self.assertEqual(self.dashboard.check_blocked_user(user, user_to_block_not_exist), 2)


    def test_check_user_taken(self):
        # Test when the user is already taken
        username = "existing_user"
        with patch.object(self.dashboard, 'read_csv_as_df', return_value=pd.DataFrame({"username": ["existing_user"]})):
            self.assertTrue(self.dashboard.check_user_taken(username))

        # Test when the user is not taken
        username = "new_user"
        with patch.object(self.dashboard, 'read_csv_as_df', return_value=pd.DataFrame({"username": ["existing_user"]})):
            self.assertFalse(self.dashboard.check_user_taken(username))

    @patch('secrets.token_bytes')
    def test_gen_salt(self, mock_token_bytes):
        # Mock the secrets.token_bytes function to return a known value
        mock_token_bytes.return_value = b'\x8f\x15\xa5\xfe\xf6\xeb6B\x1a\xaf\xeaJ\x06x\x18\xfc'
        expected_salt = '8f15a5fef6eb36421aafea4a067818fc'
        self.assertEqual(self.dashboard.gen_salt(), expected_salt)

    @patch('builtins.open', new_callable=mock_open)
    def test_add_csv_record(self, mock_open):
        mock_csv_writer = mock_open().return_value.__enter__.return_value
        self.dashboard.add_csv_record('test.csv', {'username': 'user1', 'userID': '123', 'role': 'admin'})
        

    @patch('backenddashboard.BackendDashboard.get_auth_level')
    def test_auth_action(self, mock_get_auth_level):
        # Mock the get_auth_level method
        mock_get_auth_level.side_effect = lambda x: {'admin': 2, 'user': 1}.get(x)
        # Test cases for different combinations of user and target_user roles
        self.assertFalse(self.dashboard.auth_action('admin', 'user'))
        self.assertTrue(self.dashboard.auth_action('user', 'admin'))
        self.assertTrue(self.dashboard.auth_action('user', 'user'))


    @patch('backenddashboard.BackendDashboard.read_csv_as_df')
    @patch('hashlib.sha256')
    def test_auth_login_for_admin_and_user(self, mock_sha256, mock_read_csv_as_df):
        # Setup the mock for hashing
        mock_hash_obj = MagicMock()
        mock_sha256.return_value = mock_hash_obj
        mock_hash_obj.hexdigest.side_effect = ["hashed_superadmin_pw", 'hashed_admin_pw', 'hashed_user_pw']

        # Create a mock DataFrame
        data = {
            'username': ['superadmin', 'admin2', 'earn'],
            "userID": [0, 1, 2],
            'password': ["hashed_superadmin_pw",'hashed_admin_pw', 'hashed_user_pw'],
            'salt': ['salt_superadmin', 'salt_admin', 'salt_user'],
            'role': [0, 1, 2]
        }
        df = pd.DataFrame(data)
        mock_read_csv_as_df.return_value = df

        # Act and Assert for Admin
        result_admin = self.dashboard.auth_login('superadmin', 'superadmin1!')
        self.assertEqual(result_admin, '0')  # Assuming 'admin' is the auth level for "admin2"

        # Act and Assert for Admin
        result_admin = self.dashboard.auth_login('admin2', 'Admin1!')
        self.assertEqual(result_admin, '1')  # Assuming 'admin' is the auth level for "admin2"

        # Act and Assert for User
        result_user = self.dashboard.auth_login('earn', 'Earn1!')
        self.assertEqual(result_user, '2')  # Assuming 'user' is the auth level for "earn"

if __name__ == '__main__':
    unittest.main()
    

