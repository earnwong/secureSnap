import unittest
from unittest.mock import patch, MagicMock
from backenddashboard import BackendDashboard
import pandas as pd

class TestBackendDashboard(unittest.TestCase):
    def setUp(self):
        self.dashboard = BackendDashboard()


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
    
