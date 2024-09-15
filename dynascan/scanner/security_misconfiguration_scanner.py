import requests

from urllib.parse import urljoin


# Scans the provided URL for various security misconfigurations.
def scan_security_misconfigurations(url):

    results = []

    # Check for missing security headers

    missing_headers = scan_for_missing_headers(url)

    if missing_headers:

        for header in missing_headers:

            results.append(f"{header} header not set")

    # Scan for RIA (Rich Internet Application) policy files

    ria_vulnerabilities = scan_for_ria_policy_files(url)

    if ria_vulnerabilities:

        results.extend(ria_vulnerabilities)

    # Scan for improper logging

    improper_logging_issues = scan_for_improper_logging(url)

    if improper_logging_issues:

        results.extend(improper_logging_issues)

    # Scan for XXE (XML External Entity) injection vulnerabilities

    xxe_vulnerabilities = scan_for_xxe_injection(url)

    if xxe_vulnerabilities:

        results.extend(xxe_vulnerabilities)

    # Scan for Tag Injection vulnerabilities

    tag_injection_vulnerabilities = scan_for_tag_injection(url)

    if tag_injection_vulnerabilities:

        results.extend(tag_injection_vulnerabilities)

    return results


def scan_for_missing_headers(url):

    # Checks the provided URL for missing security headers.

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

        print(f"Error fetching URL {url}: {reqexception}")

    return missing_headers


def load_headers(file_name):

    headers = []

    try:

        with open(file_name, "r") as file:

            headers = [line.strip() for line in file.readlines()]

    except FileNotFoundError:

        print(f"File {file_name} not found.")

    return headers


def scan_for_ria_policy_files(base_url):

    # Checks for RIA policy files that may be overly permissive.

    policy_files = ["crossdomain.xml", "clientaccesspolicy.xml"]

    vulnerabilities = []

    for policy_file in policy_files:

        policy_url = urljoin(base_url, policy_file)

        try:

            response = requests.get(policy_url)

            if response.status_code == 200 and "*" in response.text:

                vulnerabilities.append(f"Overly permissive policy file found")

        except requests.RequestException as reqexception:

            vulnerabilities.append(
                f"Error accessing {policy_file} at {policy_url}: {reqexception}"
            )

    return vulnerabilities


def scan_for_improper_logging(url):

    # Checks for improper logging that may expose sensitive data.

    logging_issues = []

    sensitive_words = ["password", "credit card", "ssn", "private key", "secret"]

    try:

        response = requests.get(url)

        for word in sensitive_words:

            if word in response.text.lower():

                logging_issues.append(f"Sensitive data found in logs: {word}")

    except requests.RequestException as reqexception:

        logging_issues.append(
            f"Error while checking for logging issues at {url}: {reqexception}"
        )

    return logging_issues


def scan_for_xxe_injection(url):

    # Tests the provided URL for XXE (XML External Entity) injection vulnerabilities.

    xxe_payloads = load_payloads("scanner/xxe_payloads.txt")

    results = []
    detected_payloads = []

    for payload in xxe_payloads:

        try:

            response = requests.post(
                url, data=payload, headers={"Content-Type": "application/xml"}
            )
            if response.status_code == 200:
                detected_payloads.append(payload)
        except requests.RequestException as reqexception:
            results.append(
                f"Error while testing XXE injection at {url}: {reqexception}"
            )
            break

    if detected_payloads:
        results.append("XML External Entity (XXE) Injection detected.")

    return results


def scan_for_tag_injection(url):

    # Tests the provided URL for Tag Injection vulnerabilities.

    tag_injection_payloads = load_payloads("scanner/tag_injection_payloads.txt")

    results = []

    detected_payloads = []

    for payload in tag_injection_payloads:

        try:

            response = requests.post(
                url, data=payload, headers={"Content-Type": "application/xml"}
            )

            if response.status_code == 200:

                detected_payloads.append(payload)

        except requests.RequestException as reqexception:

            results.append(
                f"Error while testing Tag Injection at {url}: {reqexception}"
            )

            break

    if detected_payloads:

        results.append("Tag Injection vulnerability detected.")

    return results


def load_payloads(file_name):

    payloads = []

    try:

        with open(file_name, "r") as file:

            payloads = [line.strip() for line in file.readlines()]

    except FileNotFoundError:

        print(f"File {file_name} not found.")

    return payloads
