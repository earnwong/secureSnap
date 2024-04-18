import unittest
from unittest.mock import patch, MagicMock
import client.dashboard as dashboard  
from client.dashboard import Dashboard
import easygui

class TestDashboard(unittest.TestCase):

    @patch('dashboard.easygui.fileopenbox')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data=b"test data")
    def test_select_photo(self, mock_open, mock_fileopenbox):
        mock_fileopenbox.return_value = 'test_file_path'
        mock_client_socket = MagicMock()

        dashboard = Dashboard(mock_client_socket)
        dashboard.select_photo()

        mock_fileopenbox.assert_called_once_with(msg="Select a file to send", title="Select File")
        mock_open.assert_called_once_with('test_file_path', 'rb')
        mock_client_socket.sendall.assert_called_with(b"test data")

if __name__ == '__main__':
    unittest.main()
