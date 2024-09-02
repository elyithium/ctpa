import requests

def scan_xss(url, params):
    payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
    vulnerabilities = []
    for param in params:
        for payload in payloads:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(url, params=test_params)
            if payload in response.text:
                vulnerabilities.append({
                    "issue": "Cross-Site Scripting (XSS)",
                    "description": f"XSS vulnerability detected using payload: {payload}.",
                    "severity": "High",
                    "endpoint": url
                })
    return vulnerabilities
