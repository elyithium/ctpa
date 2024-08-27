import requests

def scan_security_misconfigurations(url):
    response = requests.get(url)
    vulnerabilities = []
    if "X-Frame-Options" not in response.headers:
        vulnerabilities.append("X-Frame-Options header missing")
    if "X-Content-Type-Options" not in response.headers:
        vulnerabilities.append("X-Content-Type-Options header missing")
    if "Content-Security-Policy" not in response.headers:
        vulnerabilities.append("Content-Security-Policy header missing")
    return vulnerabilities

#test to push