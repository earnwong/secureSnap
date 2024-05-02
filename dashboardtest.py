import unittest
from unittest.mock import patch, MagicMock
from dashboard import Dashboard  # Assuming your module is named dashboard


class TestDashboard(unittest.TestCase):

    @patch('easygui.fileopenbox', return_value="test_image.jpg")
    @patch('os.path.getsize', return_value=1000000)  # 1 MB
    @patch('imghdr.what', return_value='jpg')
    def test_select_photo_valid(self, mock_imghdr, mock_os_path_getsize, mock_easygui_fileopenbox):
        dashboard = Dashboard(MagicMock())
        file_path = dashboard.select_photo()
        self.assertEqual(file_path, "test_image.jpg")


if __name__ == '__main__':
    unittest.main()
