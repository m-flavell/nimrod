import unittest
from unittest.mock import patch, MagicMock
import urllib.error
import base64

import json

# Import the function we want to test
from sqli import test_sql_injection, _tamper_json_payload, test_sql_injection_json

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

    def test_tamper_json_payload(self):
        payload = {
            "name": "test",
            "age": 25,
            "metadata": {
                "tag": "user",
                "score": 9.5
            },
            "history": ["login", 123, "logout"]
        }

        tampered = _tamper_json_payload(payload, "'")

        # Check string values are tampered
        self.assertEqual(tampered["name"], "test'")
        self.assertEqual(tampered["metadata"]["tag"], "user'")
        self.assertEqual(tampered["history"][0], "login'")
        self.assertEqual(tampered["history"][2], "logout'")

        # Check non-string values are untouched
        self.assertEqual(tampered["age"], 25)
        self.assertEqual(tampered["metadata"]["score"], 9.5)
        self.assertEqual(tampered["history"][1], 123)

    @patch('sqli.urllib.request.urlopen')
    @patch('sqli.urllib.request.Request')
    def test_sql_injection_json(self, mock_request, mock_urlopen):
        # Create a mock request object
        mock_req_instance = MagicMock()
        mock_request.return_value = mock_req_instance

        # Create a mock response object indicating failure (SQL error found)
        mock_response = MagicMock()
        mock_response.read.return_value = b"Warning: mysql syntax error"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        payload = {"username": "admin"}

        is_successful, error_message = test_sql_injection_json(
            "api.example.com",
            json_payload=payload,
            method="POST",
            username="testuser",
            password="testpassword"
        )

        self.assertTrue(is_successful)

        # Verify JSON was tampered and used as data
        expected_tampered_payload = {"username": "admin'"}
        expected_data = json.dumps(expected_tampered_payload).encode('utf-8')
        mock_request.assert_called_with("https://api.example.com/", data=expected_data, method="POST")

        # Verify headers
        mock_req_instance.add_header.assert_any_call('Content-Type', 'application/json')
        expected_auth = base64.b64encode(b"testuser:testpassword").decode('utf-8')
        mock_req_instance.add_header.assert_any_call('Authorization', f'Basic {expected_auth}')

if __name__ == '__main__':
    unittest.main()
