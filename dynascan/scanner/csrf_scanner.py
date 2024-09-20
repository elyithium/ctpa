import requests

# A list of payloads to simulate various form submissions
CSRF_PAYLOADS = [
    {"email": "attacker@evil.com"},  # Test email update
    {"username": "attacker"},         # Test username update
    {"password": "newpassword123"},   # Test password change
    {"address": "1234 Fake St."},     # Test address update
]

def send_csrf_payload(url, payload, token=None):
    """
    Send a CSRF payload to the server and analyze the response.
    Arguments:
    - url: The URL of the form page to scan for CSRF vulnerabilities.
    - payload: The data to send in the form, simulating a CSRF attack.
    - token: Optional CSRF token to include in the request (if provided).
    Returns:
    - str: A description of the issue if a vulnerability is found, else None.
    """
    try:
        # If a CSRF token is provided, add it to the payload
        if token:
            payload["CSRFToken"] = token

        # Send the payload to the server
        response = requests.post(url, data=payload)

        # Extract the form field for reporting purposes
        field = list(payload.keys())[0]

        # Check if the request is accepted without the CSRF token
        if response.status_code == 200:
            # If no token, vulnerability is detected
            if token is None:
                return f"CSRF vulnerability detected: Request accepted without CSRF token for '{field}'."
            else:
                return f"CSRF token validation passed for the field '{field}'."
        return None

    except Exception as e:
        print(f"Error during CSRF payload test: {e}")
        return None

def scan_csrf(url):
    """
    Scan for CSRF vulnerabilities by testing multiple payloads with and without CSRF tokens.
    Stop testing for a payload once a vulnerability is detected.
    Arguments:
    - url: The URL of the form page to scan for CSRF vulnerabilities.
    Returns:
    - A list of issues detected, or an empty list if none are found.
    """
    issues = []

    # Case 1: Test all payloads without a CSRF token (simulate attack)
    for payload in CSRF_PAYLOADS:
        result_no_token = send_csrf_payload(url, payload)
        if result_no_token:
            issues.append(result_no_token)
            # Skip testing with the token if the request is accepted without a CSRF token
            continue

        # Case 2: Test with a valid CSRF token (only if no vulnerability was found)
        valid_token = "valid_token_example"  # Replace with a real token if available
        result_with_token = send_csrf_payload(url, payload, token=valid_token)
        if result_with_token:
            issues.append(result_with_token)

    return issues
