import unittest
from unittest.mock import patch, MagicMock
import urllib.error
import base64

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

    @patch('sqli.urllib.request.urlopen')
    @patch('sqli.urllib.request.Request')
    def test_sql_injection_with_method_and_auth(self, mock_request, mock_urlopen):
        # Create a mock request object
        mock_req_instance = MagicMock()
        mock_request.return_value = mock_req_instance

        # Create a mock response object
        mock_response = MagicMock()
        mock_response.read.return_value = b"Some text with You have an error in your SQL syntax here"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        is_successful, error_message = test_sql_injection(
            "api.example.com",
            method="PUT",
            username="admin",
            password="mypassword"
        )

        self.assertTrue(is_successful)

        # Verify Request was instantiated with method PUT
        mock_request.assert_called_with("https://api.example.com/?id=%27", method="PUT")

        # Verify the Authorization header was set
        expected_auth = base64.b64encode(b"admin:mypassword").decode('utf-8')
        mock_req_instance.add_header.assert_any_call('Authorization', f'Basic {expected_auth}')

if __name__ == '__main__':
    unittest.main()
