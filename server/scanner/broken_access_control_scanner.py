import requests

def hijack_session(url, session_token):
    headers = {"Cookie": f"session_id={session_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return {
            "issue": "Hijack a session",
            "description": f"Session hijacked successfully with session token: {session_token}",
            "severity": "High"
        }
    return {
        "issue": "Hijack a session",
        "description": f"Session hijack failed with session token: {session_token}",
        "severity": "Low"
    }

def test_idor(url, object_reference):
    params = {"user_id": object_reference}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return {
            "issue": "Insecure Direct Object References (IDOR)",
            "description": f"IDOR vulnerability found with object reference: {object_reference}",
            "severity": "High"
        }
    return {
        "issue": "Insecure Direct Object References (IDOR)",
        "description": f"No IDOR vulnerability detected with object reference: {object_reference}",
        "severity": "Low"
    }

def test_function_level_access(url, role):
    payload = {"user_role": role}
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        return {
            "issue": "Missing Function Level Access Control",
            "description": f"Unauthorized access detected for role: {role}",
            "severity": "High"
        }
    return {
        "issue": "Missing Function Level Access Control",
        "description": f"Access denied for role: {role}",
        "severity": "Low"
    }

def spoof_auth_cookie(url, spoofed_cookie_value):
    headers = {"Cookie": f"auth_token={spoofed_cookie_value}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return {
            "issue": "Spoofing an Authentication Cookie",
            "description": f"Spoofed cookie allowed unauthorized access with auth token: {spoofed_cookie_value}",
            "severity": "High"
        }
    return {
        "issue": "Spoofing an Authentication Cookie",
        "description": f"Cookie spoofing failed with auth token: {spoofed_cookie_value}",
        "severity": "Low"
    }

def scan_broken_access_control(url, params):
    vulnerabilities = []

    # Test for session hijacking
    session_token = "sample_token_to_hijack"
    vulnerabilities.append(hijack_session(url, session_token))

    # Test for IDOR
    object_reference = "1234"
    vulnerabilities.append(test_idor(url, object_reference))

    # Test for missing function-level access control
    roles = ["admin", "guest", "user"]
    for role in roles:
        vulnerabilities.append(test_function_level_access(url, role))

    # Test for spoofing authentication cookies
    spoofed_cookie = "fake_auth_token"
    vulnerabilities.append(spoof_auth_cookie(url, spoofed_cookie))

    return vulnerabilities
