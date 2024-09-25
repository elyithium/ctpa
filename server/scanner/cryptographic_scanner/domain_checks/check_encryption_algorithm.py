# Check for Strong or Weak Encryption Algorithms
def check_encryption_algorithm(encryption_algo, domain):
    if 'AES' in encryption_algo or 'ChaCha20' in encryption_algo:
        return {
            "issue": "Encryption",
            "description": f"{encryption_algo} is a strong encryption algorithm.",
            "severity": "Informational",
            "endpoint": domain
        }
    elif '3DES' in encryption_algo or 'DES' in encryption_algo or 'RC4' in encryption_algo:
        return {
            "issue": "Encryption",
            "description": f"{encryption_algo} is weak and insecure.",
            "severity": "High",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Encryption",
            "description": f"{encryption_algo} is an unknown or potentially insecure encryption algorithm.",
            "severity": "Medium",
            "endpoint": domain
        }
