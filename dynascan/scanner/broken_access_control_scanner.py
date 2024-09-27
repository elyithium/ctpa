import requests

def hijack_session(url, session_token):
    headers = {"Cookie": f"session_id={session_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return "Hijack a session", "Session hijacked successfully"
    return "Hijack a session", "Session hijack failed"

def test_idor(url, object_reference):
    params = {"user_id": object_reference}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return "Insecure Direct Object References (IDOR)", "IDOR vulnerability found"
    return "Insecure Direct Object References (IDOR)", "No IDOR vulnerability detected"

def test_function_level_access(url, role):
    payload = {"user_role": role}
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        return "Missing Function Level Access Control", f"Unauthorized access detected for role: {role}"
    return "Missing Function Level Access Control", f"Access denied for role: {role}"

def spoof_auth_cookie(url, spoofed_cookie_value):
    headers = {"Cookie": f"auth_token={spoofed_cookie_value}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return "Spoofing an Authentication Cookie", "Spoofed cookie allowed unauthorized access"
    return "Spoofing an Authentication Cookie", "Cookie spoofing failed"

def scan_broken_access_control(url, params):
    vulnerabilities = []
    
    # Test for session hijacking
    session_token = "sample_token_to_hijack"
    hijack_result = hijack_session(url, session_token)
    vulnerabilities.append(hijack_result)
    
    # Test for IDOR
    object_reference = "1234"
    idor_result = test_idor(url, object_reference)
    vulnerabilities.append(idor_result)
    
    # Test for missing function-level access control
    roles = ["admin", "guest", "user"]
    for role in roles:
        function_level_result = test_function_level_access(url, role)
        vulnerabilities.append(function_level_result)
    
    # Test for spoofing authentication cookies
    spoofed_cookie = "fake_auth_token"
    spoof_result = spoof_auth_cookie(url, spoofed_cookie)
    vulnerabilities.append(spoof_result)

    # Return a summary of the findings
    simplified_results = []
    for test_name, outcome in vulnerabilities:
        if "Unauthorized access detected" in outcome:
            simplified_results.append(f"{test_name}: Unauthorized access detected ({outcome})")
        elif "vulnerability found" in outcome or "successfully" in outcome:
            simplified_results.append(f"{test_name}: {outcome}")
        else:
            simplified_results.append(f"{test_name}: No vulnerabilities detected")

    return simplified_results
