import requests
from urllib.parse import urljoin

# Scans the provided URL for various security misconfigurations.
def scan_security_misconfigurations(url):
    vulnerabilities = []

    # Check for missing security headers
    missing_headers = scan_for_missing_headers(url)
    if missing_headers:
        for header in missing_headers:
            vulnerabilities.append({
                "issue": "Missing Security Header",
                "description": f"{header} header is not set.",
                "severity": "Medium",
                "endpoint": url
            })

    # Scan for RIA (Rich Internet Application) policy files
    ria_vulnerabilities = scan_for_ria_policy_files(url)
    if ria_vulnerabilities:
        for vuln in ria_vulnerabilities:
            vulnerabilities.append({
                "issue": "Overly Permissive Policy File",
                "description": vuln,
                "severity": "High",
                "endpoint": url
            })

    # Scan for improper logging
    improper_logging_issues = scan_for_improper_logging(url)
    if improper_logging_issues:
        for issue in improper_logging_issues:
            vulnerabilities.append({
                "issue": "Improper Logging",
                "description": issue,
                "severity": "High",
                "endpoint": url
            })

    # Scan for XXE (XML External Entity) injection vulnerabilities
    xxe_vulnerabilities = scan_for_xxe_injection(url)
    if xxe_vulnerabilities:
        for vuln in xxe_vulnerabilities:
            vulnerabilities.append({
                "issue": "XXE Injection",
                "description": vuln,
                "severity": "High",
                "endpoint": url
            })

    # Scan for Tag Injection vulnerabilities
    tag_injection_vulnerabilities = scan_for_tag_injection(url)
    if tag_injection_vulnerabilities:
        for vuln in tag_injection_vulnerabilities:
            vulnerabilities.append({
                "issue": "Tag Injection",
                "description": vuln,
                "severity": "Medium",
                "endpoint": url
            })

    return vulnerabilities


def scan_for_missing_headers(url):
    headers_file = "scanner/headers.txt"
    headers = load_headers(headers_file)
    missing_headers = []

    try:
        response = requests.get(url)
        response.raise_for_status()

        for header in headers:
            if header not in response.headers:
                missing_headers.append(header)

    except requests.RequestException as reqexception:
        missing_headers.append(f"Error fetching URL {url}: {reqexception}")

    return missing_headers


def load_headers(file_name):
    try:
        with open(file_name, "r") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"File {file_name} not found.")
        return []


def scan_for_ria_policy_files(base_url):
    policy_files = ["crossdomain.xml", "clientaccesspolicy.xml"]
    vulnerabilities = []

    for policy_file in policy_files:
        policy_url = urljoin(base_url, policy_file)
        try:
            response = requests.get(policy_url)
            if response.status_code == 200 and "*" in response.text:
                vulnerabilities.append(f"Overly permissive policy file found at {policy_url}")
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
    xxe_payloads = load_payloads("scanner/xxe_payloads.txt")
    results = []

    for payload in xxe_payloads:
        try:
            response = requests.post(url, data=payload, headers={"Content-Type": "application/xml"})
            if response.status_code == 200 and "<!ENTITY" in response.text:
                results.append(f"XXE Injection detected with payload: {payload}")
        except requests.RequestException as reqexception:
            results.append(f"Error while testing XXE injection at {url}: {reqexception}")
            break

    return results


def scan_for_tag_injection(url):
    tag_injection_payloads = load_payloads("scanner/tag_injection_payloads.txt")
    results = []

    for payload in tag_injection_payloads:
        try:
            response = requests.post(url, data=payload, headers={"Content-Type": "application/xml"})
            if response.status_code == 200 and "<" in response.text:
                results.append(f"Tag Injection vulnerability detected with payload: {payload}")
        except requests.RequestException as reqexception:
            results.append(f"Error while testing Tag Injection at {url}: {reqexception}")
            break

    return results


def load_payloads(file_name):
    try:
        with open(file_name, "r") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"File {file_name} not found.")
        return []
