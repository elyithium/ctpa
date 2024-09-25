import OpenSSL

def check_public_key_length(key_size, domain):
    try:
        # Check the key length (2048 bits or higher is considered secure)
        if key_size >= 2048:
            return {
                "issue": "Public Key Length",
                "description": f"Public key length is sufficient: {key_size} bits.",
                "severity": "Informational",
                "endpoint": domain
            }
        else:
            return {
                "issue": "Public Key Length",
                "description": f"Public key length is too short: {key_size} bits.",
                "severity": "High",
                "endpoint": domain
            }
    except Exception as e:
        return {
            "issue": "Public Key Length",
            "description": f"Error checking public key length: {str(e)}",
            "severity": "High",
            "endpoint": domain
        }
