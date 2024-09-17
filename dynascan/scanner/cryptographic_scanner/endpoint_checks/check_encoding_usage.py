import base64

# Check for proper encoding usage as Base64 is vulnerable
def check_encoding_usage(data, endpoint):
    if 'base64' in data.lower():
        try:
            decoded_data = base64.b64decode(data)  # Try decoding to verify it's base64
            return {
                "issue": "Encoding Instead of Encryption",
                "description": "Sensitive data is encoded using Base64 instead of being encrypted.",
                "severity": "High",
                "details": decoded_data,
                "endpoint": endpoint
            }
        except Exception as e:
            return {
                "issue": "Invalid Encoding",
                "description": f"Error decoding Base64 data: {str(e)}",
                "severity": "High",
                "endpoint": endpoint
            }
    # If no base64 is found, return an informational result
    return {
        "issue": "Encoding Check",
        "description": "No Base64 encoding detected.",
        "severity": "Informational",
        "endpoint": endpoint
    }
