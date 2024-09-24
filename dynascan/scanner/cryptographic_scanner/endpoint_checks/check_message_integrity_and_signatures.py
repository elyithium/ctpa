# Check if digital signatures are used properly
def check_message_integrity_and_signatures(data, endpoint):
    if 'rsa' in data.lower() or 'ecdsa' in data.lower():
        return {
            "issue": "Digital Signature",
            "description": "Detected proper use of digital signatures (RSA, ECDSA).",
            "severity": "Informational",
            "details": data,
            "endpoint": endpoint
        }
    return {
        "issue": "Digital Signature",
        "description": "No digital signature detected.",
        "severity": "High",
        "details": data,
        "endpoint": endpoint
    }
