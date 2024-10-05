# Check key exchange
def check_key_exchange(key_exchange_algo, domain="N/A"):
    if 'RSA' in key_exchange_algo:
        return {
            "issue": "Weak Key Exchange Algorithm",
            "description": "RSA key exchange does not provide forward secrecy.",
            "severity": "High",
            "endpoint": domain
        }
    elif 'ECDHE' in key_exchange_algo:
        return {
            "issue": "Strong Key Exchange Algorithm",
            "description": "ECDHE key exchange provides forward secrecy.",
            "severity": "Informational",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown Key Exchange Algorithm",
            "description": f"Key exchange algorithm {key_exchange_algo} is not recognized.",
            "severity": "Medium",
            "endpoint": domain
        }
