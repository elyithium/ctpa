import requests
import base64

def scan_insecure_deserialization(url, param_name):
    vulnerabilities = []
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Example payloads to test for insecure deserialization
    payloads = [
        {
            'payload': base64.b64encode(b"test").decode(),
            'description': 'Simple string payload to test basic deserialization handling.'
        },
        {
            'payload': base64.b64encode(b"../../../../etc/passwd").decode(),
            'description': 'Attempt to perform path traversal through deserialization.'
        },
        {
            'payload': base64.b64encode(b"<script>alert(1)</script>").decode(),
            'description': 'Injected script tag to test for XSS via deserialization.'
        },
        {
            'payload': base64.b64encode(b'{"username": "admin", "role": "admin"}').decode(),
            'description': 'Serialized JSON object attempting to escalate privileges.'
        },
        {
            'payload': base64.b64encode(b"__import__('os').system('ls')").decode(),
            'description': 'Payload attempting to execute system commands via deserialization.'
        },
    ]

    for item in payloads:
        payload = item['payload']
        payload_description = item['description']
        data = {param_name: payload}
        try:
            response = requests.post(url, data=data, headers=headers, timeout=10)
            # Analyze the response for signs of vulnerability
            if response.status_code >= 500:
                vulnerabilities.append({
                    'issue': 'Server Error During Deserialization',
                    'description': f"The application threw a server error when deserializing payload: {payload_description}",
                    'severity': 'High',
                    'payload': payload,
                    'evidence': f"HTTP {response.status_code} Server Error"
                })
            elif "exception" in response.text.lower() or "error" in response.text.lower():
                vulnerabilities.append({
                    'issue': 'Exception Revealed During Deserialization',
                    'description': f"An exception was revealed when processing payload: {payload_description}",
                    'severity': 'Medium',
                    'payload': payload,
                    'evidence': "Exception or error message in response"
                })
            elif response.status_code == 200:
                vulnerabilities.append({
                    'issue': 'Potential Insecure Deserialization',
                    'description': f"The application accepted and processed payload without validation: {payload_description}",
                    'severity': 'Medium',
                    'payload': payload,
                    'evidence': "Received HTTP 200 OK"
                })
            else:
                vulnerabilities.append({
                    'issue': 'Unexpected Behavior During Deserialization',
                    'description': f"The application returned an unexpected status code when processing payload: {payload_description}",
                    'severity': 'Low',
                    'payload': payload,
                    'evidence': f"HTTP {response.status_code}"
                })
        except requests.exceptions.Timeout:
            vulnerabilities.append({
                'issue': 'Denial of Service via Deserialization',
                'description': f"The application became unresponsive when processing payload: {payload_description}",
                'severity': 'High',
                'payload': payload,
                'evidence': 'Request timed out'
            })
        except Exception as e:
            vulnerabilities.append({
                'issue': 'Error Occurred During Deserialization Testing',
                'description': f"An unexpected error occurred when testing payload: {payload_description}",
                'severity': 'Low',
                'payload': payload,
                'evidence': f"Exception: {e}"
            })

    return vulnerabilities