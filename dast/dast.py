import requests
import csv
from urllib.parse import urljoin

#A03:2021-Injection
# SQL Injection Scanner
def scan_sql_injection(url, params):
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]
    vulnerabilities = []
    for param in params:
        for payload in payloads:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(url, params=test_params)
            if "syntax error" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
                vulnerabilities.append((param, payload))
    return vulnerabilities

# Cross-Site Scripting (XSS) Scanner
def scan_xss(url, params):
    payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
    vulnerabilities = []
    for param in params:
        for payload in payloads:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(url, params=test_params)
            if payload in response.text:
                vulnerabilities.append((param, payload))
    return vulnerabilities

# A07:2021-Identification and Authentication Failures
# Broken Authentication Scanner (Basic check for insecure authentication)
def scan_broken_authentication(url, params):
    test_params = params.copy()
    test_params['password'] = 'incorrect_password'
    response = requests.post(url, data=test_params)
    vulnerabilities = []
    if "incorrect password" not in response.text.lower() and response.status_code == 200:
        vulnerabilities.append("Possible broken authentication detected")
    return vulnerabilities

# A02:2021-Cryptographic Failures Scanner (Check for HTTPS)
def scan_sensitive_data_exposure(url):
    vulnerabilities = []
    if not url.startswith("https://"):
        vulnerabilities.append("Sensitive data may be exposed, connection is not HTTPS")
    return vulnerabilities

# A01:2021-Broken Access Control Scanner (Check for unauthorized access)
def scan_broken_access_control(url):
    response = requests.get(url)
    vulnerabilities = []
    if response.status_code == 200 and "unauthorized" not in response.text.lower():
        vulnerabilities.append("Access control issue, unauthorized access allowed")
    return vulnerabilities

# A08:2021-Software and Data Integrity Failures Scanner
def scan_insecure_deserialization(url, params):
    payload = '{"username": "admin", "role": "admin"}'  # Example payload
    response = requests.post(url, data=payload, headers={"Content-Type": "application/json"})
    vulnerabilities = []
    if "admin" in response.text:
        vulnerabilities.append("Software and Data Integrity Failures  detected")
    return vulnerabilities

# A05:2021-Security Misconfiguration Scanner (already implemented)
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

# Vulnerability Scanner Class
class VulnerabilityScanner:
    def __init__(self, base_url, endpoints):
        self.base_url = base_url
        self.endpoints = endpoints
        self.results = []

    def run_scans(self):
        for endpoint, params in self.endpoints.items():
            url = urljoin(self.base_url, endpoint)
            print(f"Scanning {url}...")
            
            # Run each scanner
            sql_vulns = scan_sql_injection(url, params)
            xss_vulns = scan_xss(url, params)
            auth_vulns = scan_broken_authentication(url, params)
            data_vulns = scan_sensitive_data_exposure(url)
            access_vulns = scan_broken_access_control(url)
            deserialization_vulns = scan_insecure_deserialization(url, params)
            config_vulns = scan_security_misconfigurations(url)
            
            # Collect results
            if sql_vulns:
                self.results.append({"type": "SQL Injection", "endpoint": url, "vulnerabilities": sql_vulns})
            if xss_vulns:
                self.results.append({"type": "XSS", "endpoint": url, "vulnerabilities": xss_vulns})
            if auth_vulns:
                self.results.append({"type": "Broken Authentication", "endpoint": url, "vulnerabilities": auth_vulns})
            if data_vulns:
                self.results.append({"type": "Sensitive Data Exposure", "endpoint": url, "vulnerabilities": data_vulns})
            if access_vulns:
                self.results.append({"type": "Broken Access Control", "endpoint": url, "vulnerabilities": access_vulns})
            if deserialization_vulns:
                self.results.append({"type": "Insecure Deserialization", "endpoint": url, "vulnerabilities": deserialization_vulns})
            if config_vulns:
                self.results.append({"type": "Security Misconfiguration", "endpoint": url, "vulnerabilities": config_vulns})
    
    def generate_report(self):
        print("Scan Results:")
        for result in self.results:
            print(f"Vulnerability: {result['type']} detected at {result['endpoint']}")
            for vuln in result['vulnerabilities']:
                if isinstance(vuln, tuple):
                    print(f"  - Parameter: {vuln[0]} | Payload: {vuln[1]}")
                else:
                    print(f"  - Issue: {vuln}")
                    

# webgoat usage
if __name__ == "__main__":
    endpoints = {
        "WebGoat/SqlInjection/attack": {"username": "test", "password": "test"},
        "WebGoat/XSS/attack": {"q": "test"},
        "WebGoat/Auth/login": {"username": "test", "password": "test"},
        "WebGoat/SensitiveData": {},
        "WebGoat/AccessControl/attack": {},
        "WebGoat/Deserialization/attack": {"data": "test"}
    }

    scanner = VulnerabilityScanner("http://127.0.0.1:8080/", endpoints)
    scanner.run_scans()
    scanner.generate_report()

