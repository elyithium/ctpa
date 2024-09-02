import requests

def scan_broken_authentication(url, params):
    test_params = params.copy()
    test_params['password'] = 'incorrect_password'
    response = requests.post(url, data=test_params)
    vulnerabilities = []
    if "incorrect password" not in response.text.lower() and response.status_code == 200:
        vulnerabilities.append({
            "issue": "Broken Authentication",
            "description": "Possible broken authentication detected.",
            "severity": "High",
            "endpoint": url
        })
    return vulnerabilities
