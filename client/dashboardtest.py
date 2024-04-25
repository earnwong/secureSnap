import io
import unittest
from unittest.mock import MagicMock, mock_open, patch
from dashboard import Dashboard
import easygui


class TestDashboard(unittest.TestCase):
    def setUp(self):
        # Mock a client socket
        self.mock_socket = MagicMock()
        self.dashboard = Dashboard(self.mock_socket)

    @patch('easygui.fileopenbox')
    @patch('builtins.open', new_callable=mock_open, read_data=b"fake data")
    @patch('easygui.msgbox')
    def test_select_photo_with_file(self, mock_msgbox, mock_open, mock_fileopenbox):
        # Setup the mock to return a file path
        mock_fileopenbox.return_value = '/fake/path.jpg'

        self.dashboard.select_photo('recipient')

        # Assert
        mock_fileopenbox.assert_called_once_with(msg="Select a file to send", title="Select File")
        mock_open.assert_called_once_with('/fake/path.jpg', 'rb')
        self.mock_socket.sendall.assert_called_with(b"fake data")
        mock_msgbox.assert_called_once_with("Photo sent to recipient", title="User Selection")
        print("File sent successfully.")

    @patch('easygui.fileopenbox')
    @patch('sys.stdout', new_callable=io.StringIO)
    def test_select_photo_no_file_selected(self, mock_stdout, mock_fileopenbox):
        # Setup the mock to return None, simulating no file selected
        mock_fileopenbox.return_value = None

        self.dashboard.select_photo('recipient')

        # Assert
        mock_fileopenbox.assert_called_once_with(msg="Select a file to send", title="Select File")
        self.assertEqual("No file selected.\n", mock_stdout.getvalue())

if __name__ == '__main__':
    unittest.main()
