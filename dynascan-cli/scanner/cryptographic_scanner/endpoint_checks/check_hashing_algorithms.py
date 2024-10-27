import re

# Check for weak or deprecated hashing algorithms
def check_hashing_algorithms(data, endpoint):
    if 'md5' in data.lower() or re.search(r'\b[0-9a-f]{32}\b', data):
        return {
            "issue": "Weak Hashing Algorithm",
            "description": "Detected MD5 hashing algorithm.",
            "severity": "High",
            "details": data,
            "endpoint": endpoint
        }
    elif 'sha1' in data.lower() or re.search(r'\b[0-9a-f]{40}\b', data):
        return {
            "issue": "Weak Hashing Algorithm",
            "description": "Detected SHA-1 hashing algorithm.",
            "severity": "High",
            "details": data,
            "endpoint": endpoint
        }
    elif 'sha256' in data.lower() or re.search(r'\b[0-9a-f]{64}\b', data):
        return {
            "issue": "Hashing Algorithm",
            "description": "Detected SHA-256 hashing algorithm.",
            "severity": "Informational",
            "details": data,
            "endpoint": endpoint
        }
    elif 'sha512' in data.lower() or re.search(r'\b[0-9a-f]{128}\b', data):
        return {
            "issue": "Hashing Algorithm",
            "description": "Detected SHA-512 hashing algorithm.",
            "severity": "Informational",
            "details": data,
            "endpoint": endpoint
        }

    # If no hashing algorithm issues are detected, return an informational result
    return {
        "issue": "Hashing Algorithm Check",
        "description": "No weak or deprecated hashing algorithms detected.",
        "severity": "Informational",
        "endpoint": endpoint
    }
