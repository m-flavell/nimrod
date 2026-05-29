import urllib.request
import urllib.error
import urllib.parse
import ssl
import base64
import json
import copy
from typing import Tuple, Optional, Dict, Any

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlite3::sqlexception"
]

def test_sql_injection(
    fqdn: str,
    method: str = "GET",
    username: Optional[str] = None,
    password: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Tests an API for SQL injection vulnerabilities using a common payload.

    Args:
        fqdn (str): The Fully Qualified Domain Name of the API to test (e.g., api.example.com).
        method (str): The HTTP method to use (e.g., "GET", "POST", "PUT"). Defaults to "GET".
        username (Optional[str]): Username for Basic Authentication.
        password (Optional[str]): Password for Basic Authentication.

    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating if an SQL injection
                          vulnerability was found, and the error message returned.
    """
    payload = "'"
    # Ensure fqdn does not have a trailing slash
    fqdn = fqdn.rstrip('/')

    urls = [
        f"https://{fqdn}/?id={urllib.parse.quote(payload)}",
        f"http://{fqdn}/?id={urllib.parse.quote(payload)}"
    ]

    # Ignore SSL errors for testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, method=method.upper())
            # Add a user agent to avoid some basic blocks
            req.add_header('User-Agent', 'Mozilla/5.0 (SQLi Test)')

            # Add Basic Authentication if provided
            if username is not None and password is not None:
                auth_str = f"{username}:{password}"
                auth_bytes = auth_str.encode('utf-8')
                auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')
                req.add_header('Authorization', f'Basic {auth_base64}')

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                body = response.read().decode('utf-8', errors='ignore')

                # Check for SQL error patterns in response body
                for error_pattern in SQL_ERRORS:
                    if error_pattern in body.lower():
                        return True, body

        except urllib.error.HTTPError as e:
            # Often SQL injections result in 500 Internal Server Error
            error_body = e.read().decode('utf-8', errors='ignore')
            for error_pattern in SQL_ERRORS:
                if error_pattern in error_body.lower():
                    return True, error_body
            # If no specific pattern but it's an error, we might still want to look at it,
            # but we'll strictly check for known patterns to avoid false positives.

        except urllib.error.URLError:
            # E.g., connection refused, try next URL (fallback to http)
            continue
        except Exception:
            # Other errors
            continue

    return False, ""

def _tamper_json_payload(payload: Dict[str, Any], tamper_str: str) -> Dict[str, Any]:
    """Recursively traverses a dictionary and appends a tamper string to all string values."""
    tampered = copy.deepcopy(payload)
    def traverse_and_tamper(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    obj[k] = v + tamper_str
                elif isinstance(v, (dict, list)):
                    traverse_and_tamper(v)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                if isinstance(v, str):
                    obj[i] = v + tamper_str
                elif isinstance(v, (dict, list)):
                    traverse_and_tamper(v)

    traverse_and_tamper(tampered)
    return tampered

def test_sql_injection_json(
    fqdn: str,
    json_payload: Dict[str, Any],
    method: str = "POST",
    username: Optional[str] = None,
    password: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Tests an API for SQL injection vulnerabilities by tampering a JSON payload.

    Args:
        fqdn (str): The Fully Qualified Domain Name of the API to test.
        json_payload (Dict[str, Any]): The original JSON payload to tamper with.
        method (str): The HTTP method to use (e.g., "POST", "PUT"). Defaults to "POST".
        username (Optional[str]): Username for Basic Authentication.
        password (Optional[str]): Password for Basic Authentication.

    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating if an SQL injection
                          vulnerability was found, and the error message returned.
    """
    payload_tamper = "'"
    # Ensure fqdn does not have a trailing slash
    fqdn = fqdn.rstrip('/')

    urls = [
        f"https://{fqdn}/",
        f"http://{fqdn}/"
    ]

    # Tamper the payload
    tampered_payload_dict = _tamper_json_payload(json_payload, payload_tamper)
    tampered_data = json.dumps(tampered_payload_dict).encode('utf-8')

    # Ignore SSL errors for testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, data=tampered_data, method=method.upper())
            req.add_header('User-Agent', 'Mozilla/5.0 (SQLi Test JSON)')
            req.add_header('Content-Type', 'application/json')

            # Add Basic Authentication if provided
            if username is not None and password is not None:
                auth_str = f"{username}:{password}"
                auth_bytes = auth_str.encode('utf-8')
                auth_base64 = base64.b64encode(auth_bytes).decode('utf-8')
                req.add_header('Authorization', f'Basic {auth_base64}')

            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                body = response.read().decode('utf-8', errors='ignore')

                for error_pattern in SQL_ERRORS:
                    if error_pattern in body.lower():
                        return True, body

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='ignore')
            for error_pattern in SQL_ERRORS:
                if error_pattern in error_body.lower():
                    return True, error_body

        except urllib.error.URLError:
            continue
        except Exception:
            continue

    return False, ""
