import requests

def scan_broken_access_control(url):
    response = requests.get(url)
    vulnerabilities = []
    if response.status_code == 200 and "unauthorized" not in response.text.lower():
        vulnerabilities.append("Access control issue, unauthorized access allowed")
    return vulnerabilities
