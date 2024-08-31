import os
import requests

# Function to load headers from a file
def load_headers(file_name):

    file_path = os.path.join(os.path.dirname(__file__), file_name)

    headers = []

    try:

        with open(file_path, 'r') as file:

            headers = [line.strip() for line in file.readlines()]

    except FileNotFoundError:

        print(f"File {file_name} not found in {file_path}")

    return headers

# List of headers to check
headers_file = 'headers.txt'

Header_list = load_headers(headers_file)

def scan_security_misconfigurations(url):

    try:

        # Sending an HTTP GET request to the provided URL
        response = requests.get(url)
        # Check if the request returned an HTTP error
        response.raise_for_status()  

    except requests.RequestException as reqexceptions:

        return [f"Error fetching URL {url}: {reqexceptions}"]
    
    # Checking for missing headers
    missing_headers = []

    for header in Header_list:

        if header not in response.headers:

            missing_headers.append(f"{header} header missing")

    # Scan for RIA policy files
    ria_vulnerabilities = scan_for_ria_policy_files(url)

    # Scan for improper logging
    improper_logging_issues = scan_for_improper_logging(url)

    return missing_headers + ria_vulnerabilities + improper_logging_issues

def scan_for_ria_policy_files(base_url):

    # List of RIA policy files to check for
    policy_files = ["crossdomain.xml", "clientaccesspolicy.xml"]

    vulnerabilities = []

    # Iterate over the policy files and construct the URL
    for policy_file in policy_files:

        policy_url = f"{base_url}/{policy_file}"

        try:

            # Send a GET request to the policy file URL
            response = requests.get(policy_url)

            # If the status is OK
            if response.status_code == 200:

                # Policy file was found
                vulnerabilities.append(f"Found {policy_file} at {policy_url}")

                # Check if the policy file is overly permissive - Policies with “*” in them should be closely examined
                if "*" in response.text:

                    vulnerabilities.append(f"Overly permissive policy found in {policy_file} at {policy_url}")

            else:

                # Policy file was not found
                vulnerabilities.append(f"{policy_file} not found at {policy_url}")

        # Handling request exceptions
        except requests.RequestException as reqexceptions:

            vulnerabilities.append(f"Error accessing {policy_file} at {policy_url}: {reqexceptions}")

    return vulnerabilities

# Scanning for improper logging
def scan_for_improper_logging(url):

    logging_issues = []

    sensitive_words = ["password", "credit card", "ssn", "private key", "secret"]

    try:

        response = requests.get(url)

        # Check the response for any sensitive keywords which should not be in the logs
        for word in sensitive_words:

            if word in response.text.lower():

                logging_issues.append(f"Sensitive data found in logs: {word}")

    except requests.RequestException as reqexceptions:

        logging_issues.append(f"Error while checking for logging issues at {url}: {reqexceptions}")

    return logging_issues

