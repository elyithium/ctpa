import requests

def scan_security_misconfigurations(url):
    response = requests.get(url)
    vulnerabilities = []
    if "X-Frame-Options" not in response.headers:
        vulnerabilities.append({
            "issue": "Security Misconfiguration",
            "description": "X-Frame-Options header missing.",
            "severity": "Medium",
            "endpoint": url
        })
    if "X-Content-Type-Options" not in response.headers:
        vulnerabilities.append({
            "issue": "Security Misconfiguration",
            "description": "X-Content-Type-Options header missing.",
            "severity": "Medium",
            "endpoint": url
        })
    if "Content-Security-Policy" not in response.headers:
        vulnerabilities.append({
            "issue": "Security Misconfiguration",
            "description": "Content-Security-Policy header missing.",
            "severity": "Medium",
            "endpoint": url
        })
    return vulnerabilities
