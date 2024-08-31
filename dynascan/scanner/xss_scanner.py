import requests

def load_payloads(file_path):

    with open(file_path, 'r') as file:

        return [line.strip() for line in file if line.strip()]

def scan_xss(url, params):

    xsspayloads_file_path = 'scanner/xss_payloads.txt'

    payloads = load_payloads(xsspayloads_file_path)

    vulnerabilities = []

    for param in params:

        for payload in payloads:

            test_params = {key: (payload if key == param else value) for key, value in params.items()}

            try:

                response = requests.get(url, params=test_params)

                if payload in response.text:

                    vulnerabilities.append((param, payload))

            except requests.RequestException as reqexception:

                print(f"Request failed: {reqexception}")

    return vulnerabilities

