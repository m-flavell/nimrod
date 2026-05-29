import unittest
from unittest.mock import patch, MagicMock
import urllib.error

# Import the function we want to test
from sqli import test_sql_injection

class TestSQLInjection(unittest.TestCase):

    @patch('sqli.urllib.request.urlopen')
    def test_sql_injection_success(self, mock_urlopen):
        # Create a mock response object
        mock_response = MagicMock()
        mock_response.read.return_value = b"Some text with You have an error in your SQL syntax here"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        is_successful, error_message = test_sql_injection("api.example.com")

        self.assertTrue(is_successful)
        self.assertIn("You have an error in your SQL syntax", error_message)

    @patch('sqli.urllib.request.urlopen')
    def test_sql_injection_failure_no_error(self, mock_urlopen):
        # Create a mock response object
        mock_response = MagicMock()
        mock_response.read.return_value = b"A normal healthy response"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        is_successful, error_message = test_sql_injection("api.example.com")

        self.assertFalse(is_successful)
        self.assertEqual(error_message, "")

    @patch('sqli.urllib.request.urlopen')
    def test_sql_injection_http_error_with_sql_error(self, mock_urlopen):
        # Mock HTTPError
        mock_error = urllib.error.HTTPError(
            url="http://api.example.com/?id=%27",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=MagicMock()
        )
        mock_error.read = MagicMock(return_value=b"Warning: mysql something went wrong")
        mock_urlopen.side_effect = mock_error

        is_successful, error_message = test_sql_injection("api.example.com")

        self.assertTrue(is_successful)
        self.assertIn("Warning: mysql", error_message)

    @patch('sqli.urllib.request.urlopen')
    def test_sql_injection_http_error_without_sql_error(self, mock_urlopen):
        # Mock HTTPError
        mock_error = urllib.error.HTTPError(
            url="http://api.example.com/?id=%27",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=MagicMock()
        )
        mock_error.read = MagicMock(return_value=b"Just a generic error")
        mock_urlopen.side_effect = mock_error

        is_successful, error_message = test_sql_injection("api.example.com")

        self.assertFalse(is_successful)
        self.assertEqual(error_message, "")

if __name__ == '__main__':
    unittest.main()
