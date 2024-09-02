import requests

def scan_sql_injection(url, params):
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]
    vulnerabilities = []
    for param in params:
        for payload in payloads:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            response = requests.get(url, params=test_params)
            if "syntax error" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
                vulnerabilities.append({
                    "issue": "SQL Injection",
                    "description": f"SQL Injection vulnerability detected using payload: {payload}",
                    "severity": "High",
                    "endpoint": url
                })
    return vulnerabilities
