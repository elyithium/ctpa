import requests

def scan_broken_access_control(url, params):
    payloads = [
        {"user_role": "admin"},  # Trying to access with an admin role
        {"user_role": "guest"},  # Trying to access with a guest role
        {"user_role": "user", "resource": "restricted_resource"},  # Attempting to access a restricted resource
        {"user_role": "user", "action": "delete"},  # Trying to perform a delete action
        {"user_role": "anonymous", "resource": "private_data"},  # Attempting to access private data as an anonymous user
        {"user_role": "user", "action": "edit"},  # Trying to perform an edit action on restricted data
    ]
    vulnerabilities = []

    for payload in payloads:
        try:
            response = requests.post(url, data=payload)
            if response.status_code == 200:
                vulnerabilities.append({
                    "issue": "Broken Access Control",
                    "description": f"Access control issue:  {response.status_code} detected with payload: {payload}. This role or action should not have access to this resource.",
                    "payload": payload,
					"severity": "High"
                })
        except requests.RequestException as e:
            vulnerabilities.append((payload, f"Error occurred: {str(e)}"))

    return vulnerabilities
