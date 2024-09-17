import requests


def load_payloads(file_path):

    #Load payloads from the provided file.

    with open(file_path, "r") as file:

        return [line.strip() for line in file if line.strip()]


def is_reflected_xss(response, payload):

    #Check if the payload is reflected in the response.

    return payload in response.text


def is_dom_based_xss(response):

    #Basic check for DOM-based XSS patterns in response.

    dom_keywords = [
        "<script>",
        "document.cookie",
        "window.location",
        "innerHTML",
        "eval(",
    ]

    return any(keyword in response.text for keyword in dom_keywords)


def scan_xss(url, params, method="GET"):

    # Scan for XSS vulnerabilities

    xsspayloads_file_path = "scanner/xss_payloads.txt"

    payloads = load_payloads(xsspayloads_file_path)

    vulnerabilities = []

    for param in params:

        for payload in payloads:

            test_params = {
                key: (payload if key == param else value)
                for key, value in params.items()
            }

            try:

                # Make the HTTP request (GET or POST based on method)

                if method == "POST":

                    response = requests.post(url, data=test_params)

                else:

                    response = requests.get(url, params=test_params)

                # Reflected XSS detection

                if is_reflected_xss(response, payload):
                    vulnerabilities.append({
                        "issue": "Reflected XSS",
                        "description": (
                            f"Reflected XSS vulnerability detected using payload: '{payload}' on parameter: '{param}'.\n"
                            f"Parameters used: {test_params}\n"
                            f"Response snippet: {response.text[:200]}..."
                        ),
                        "severity": "High",
                        "endpoint": url,
                        "payload": payload
                    })

                # DOM-based XSS detection

                if is_dom_based_xss(response):
                    vulnerabilities.append({
                        "issue": "DOM-based XSS",
                        "description": (
                            f"DOM-based XSS vulnerability detected using payload: '{payload}' on parameter: '{param}'.\n"
                            f"Parameters used: {test_params}\n"
                            f"Response snippet: {response.text[:200]}..."
                        ),
                        "severity": "High",
                        "endpoint": url,
                        "payload": payload
                    })

            except requests.RequestException as req_exception:
                vulnerabilities.append({
                    "issue": "XSS Scan Error",
                    "description": (
                        f"Error testing XSS using payload: '{payload}' on parameter: '{param}'.\n"
                        f"Parameters used: {test_params}\n"
                        f"Error: {str(req_exception)}"
                    ),
                    "severity": "High",
                    "endpoint": url,
                    "payload": payload
                })

    return vulnerabilities


def scan_stored_xss(url, post_params, check_url):

    # Scan for stored XSS by submitting POST data and checking the GET response.

    xsspayloads_file_path = "scanner/xss_payloads.txt"

    payloads = load_payloads(xsspayloads_file_path)

    vulnerabilities = []

    for param in post_params:

        for payload in payloads:

            test_params = {
                key: (payload if key == param else value)
                for key, value in post_params.items()
            }

            try:

                # Submit POST request

                post_response = requests.post(url, data=test_params)

                # Check the GET response to see if the payload is stored

                get_response = requests.get(check_url)

                # Check if payload persists (Stored XSS)

                if payload in get_response.text:

                    vulnerabilities.append((param, payload, "Stored XSS"))

            except requests.RequestException as req_exception:

                print(f"Request failed: {req_exception}")

    return vulnerabilities
