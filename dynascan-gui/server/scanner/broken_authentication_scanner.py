import requests

def scan_broken_authentication(url, params):
    test_params = params.copy()
    test_params['password'] = 'incorrect_password'
    vulnerabilities = []

    try:
        # Sending a POST request with the incorrect password
        response = requests.post(url, data=test_params)

        # Check if the incorrect password was not detected by the application
        if "incorrect password" not in response.text.lower() and response.status_code == 200:
            vulnerabilities.append({
                "issue": "Broken Authentication",
                "description": f"Possible broken authentication detected. The application did not reject the request with an incorrect password. Parameters: {test_params}.",
                "severity": "High"
            })

    except requests.RequestException as e:
        vulnerabilities.append({
            "issue": "Request Failed",
            "description": f"An error occurred during the authentication test: {str(e)}",
            "severity": "Medium"
        })

    # Return the list of vulnerabilities found
    return vulnerabilities
