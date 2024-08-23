import requests

def scan_sensitive_data_exposure(url):
    vulnerabilities = []
    if not url.startswith("https://"):
        vulnerabilities.append("Sensitive data may be exposed, connection is not HTTPS")
    return vulnerabilities
