import requests

# A list of payloads to simulate various form submissions
CSRF_PAYLOADS = [
    {"email": "attacker@evil.com"},  # Test email update
    {"username": "attacker"},         # Test username update
    {"password": "newpassword123"},   # Test password change
    {"address": "1234 Fake St."},     # Test address update
]

CSRF_ENDPOINTS = [
    "/CSRF",  # List relevant CSRF endpoints here
    "/csrf",  # Make sure to add all variations (case-sensitive)
]

def is_csrf_endpoint(url):
    """Check if the endpoint is relevant for CSRF testing."""
    for endpoint in CSRF_ENDPOINTS:
        if endpoint in url:
            return True
    return False

def send_csrf_payload(url, payload, token=None):
    try:
        # If a CSRF token is provided, add it to the payload
        if token:
            payload["OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA=="] = token

        # Send the payload to the server
        response = requests.post(url, data=payload)

        # Extract the form field for reporting purposes
        field = list(payload.keys())[0]

        # Check if the request is accepted without the CSRF token
        if response.status_code == 200:
            # If no token, vulnerability is detected
            if token is None:
                return {
                    "issue": "CSRF Vulnerability",
                    "description": f"Server accepted request without CSRF token for '{field}' submission.",
                    "severity": "High"
                }
            else:
                return {
                    "issue": "CSRF Token Validation",
                    "description": f"CSRF token validation passed for '{field}' submission.",
                    "severity": "Informational"
                }
        return None

    except Exception as e:
        return {
            "issue": "Request Error",
            "description": f"Error during CSRF payload test: {str(e)}",
            "severity": "Medium"
        }

def scan_csrf(url):
    """Scan for CSRF vulnerabilities only if the URL matches CSRF endpoints."""
    issues = []

    # Ensure we are scanning a CSRF-relevant endpoint
    if not is_csrf_endpoint(url):
        return []  # Return empty list if not a CSRF-relevant endpoint

    # Case 1: Test all payloads without a CSRF token (simulate attack)
    for payload in CSRF_PAYLOADS:
        result_no_token = send_csrf_payload(url, payload)
        if result_no_token:
            issues.append(result_no_token)
            # Skip testing with the token if the request is accepted without a CSRF token
            continue

        # Case 2: Test with a valid CSRF token (only if no vulnerability was found)
        valid_token = "OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA=="  # Replace with a real token if available
        result_with_token = send_csrf_payload(url, payload, token=valid_token)
        if result_with_token:
            issues.append(result_with_token)

    return issues
