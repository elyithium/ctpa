# web_host_scanner.py

import requests

# Define the security headers to check, along with their descriptions and severity levels
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
        "severity": "High"
    },
    "Content-Security-Policy": {
        "description": "Prevents cross-site scripting (XSS) and data injection attacks.",
        "severity": "High"
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks.",
        "severity": "Medium"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME types from being sniffed.",
        "severity": "Medium"
    },
    "Referrer-Policy": {
        "description": "Controls the amount of referrer information sent with requests.",
        "severity": "Low"
    },
    "Permissions-Policy": {
        "description": "Allows or denies the use of browser features.",
        "severity": "Low"
    }
}

def scan_web_host_info(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        # Collect all headers
        all_headers = dict(headers)

        # Initialize host_info with all headers
        host_info = {
            "URL": url,
            "all_headers": all_headers,
            "security_headers": {}
        }

        # Check for each security header
        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                host_info["security_headers"][header] = {
                    "status": "Present",
                    "value": headers[header]
                }
            else:
                host_info["security_headers"][header] = {
                    "status": "Missing",
                    "severity": info["severity"],
                    "description": info["description"]
                }
        return host_info
    except requests.RequestException as e:
        return {"error": str(e)}
