import base64
import re

def check_encoding_usage(data, endpoint):
    base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    potential_base64_strings = base64_pattern.findall(data)

    if not potential_base64_strings:
        return {
            "issue": "Encoding Check",
            "description": "No Base64 encoding detected.",
            "severity": "Informational",
            "endpoint": endpoint
        }

    for encoded_string in potential_base64_strings:
        try:
            decoded_data = base64.b64decode(encoded_string, validate=True)

            # Check for non-printable data first
            if not is_printable(decoded_data):
                return {
                    "issue": "Binary Data Detected",
                    "description": "Binary data detected, this might be sensitive information.",
                    "severity": "High",
                    "details": str(decoded_data),
                    "endpoint": endpoint
                }

            # Check for printable data if not binary
            return {
                "issue": "Encoding Instead of Encryption",
                "description": "Sensitive data is encoded using Base64 instead of being encrypted.",
                "severity": "High",
                "details": decoded_data.decode('utf-8', errors='replace'),
                "endpoint": endpoint
            }
        except (base64.binascii.Error, Exception) as e:
            # Ensure that errors are captured correctly as invalid Base64
            return {
                "issue": "Invalid Encoding",
                "description": "Error decoding Base64 data.",
                "severity": "High",
                "endpoint": endpoint
            }

    return {
        "issue": "Encoding Check",
        "description": "No valid Base64 encoding detected.",
        "severity": "Informational",
        "endpoint": endpoint
    }

# Helper function to check if the data is printable ASCII
def is_printable(data):
    return all(32 <= char < 127 for char in data)
