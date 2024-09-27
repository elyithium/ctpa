import base64
import re

# Check for proper encoding usage as Base64 is vulnerable
def check_encoding_usage(data, endpoint):
    # Define a regular expression pattern to detect potential base64 strings
    base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

    # Find all potential base64 strings in the data
    potential_base64_strings = base64_pattern.findall(data)

    # If no base64 pattern is found, return an informational result
    if not potential_base64_strings:
        return {
            "issue": "Encoding Check",
            "description": "No Base64 encoding detected.",
            "severity": "Informational",
            "endpoint": endpoint
        }

    # Try decoding each potential base64 string
    for encoded_string in potential_base64_strings:
        try:
            # Decode the string
            decoded_data = base64.b64decode(encoded_string, validate=True)  # validate=True ensures proper padding

            # Check if the decoded data is meaningful (you can add more checks here if needed)
            # For example, check if it's printable ASCII or binary data
            if is_printable(decoded_data):
                # If it's meaningful, return the issue
                return {
                    "issue": "Encoding Instead of Encryption",
                    "description": "Sensitive data is encoded using Base64 instead of being encrypted.",
                    "severity": "High",
                    "details": decoded_data.decode('utf-8', errors='replace'),  # Decode to string if possible
                    "endpoint": endpoint
                }
            else:
                # Return a separate issue for binary data (optional)
                return {
                    "issue": "Binary Data Detected",
                    "description": "Binary data detected, this might be sensitive information.",
                    "severity": "Medium",
                    "details": str(decoded_data),  # Convert binary to string representation
                    "endpoint": endpoint
                }

        except base64.binascii.Error as e:
            # Catch decoding errors
            return {
                "issue": "Invalid Encoding",
                "description": f"Error decoding Base64 data: {str(e)}",
                "severity": "High",
                "endpoint": endpoint
            }

    # If no valid base64 data is found, return an informational result
    return {
        "issue": "Encoding Check",
        "description": "No valid Base64 encoding detected.",
        "severity": "Informational",
        "endpoint": endpoint
    }

# Helper function to check if the data is printable ASCII
def is_printable(data):
    # Check if all characters in the decoded data are printable ASCII characters
    return all(32 <= char < 127 for char in data)
