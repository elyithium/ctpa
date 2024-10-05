def check_mode_of_operation(mode_of_operation, domain="N/A"):
    if mode_of_operation == 'ECB':
        return {
            "issue": "Weak Mode of Operation",
            "description": "ECB mode is insecure as it reveals patterns in the plaintext. It should not be used for sensitive data.",
            "severity": "High",
            "endpoint": domain
        }
    elif mode_of_operation in ['CBC', 'CFB', 'OFB']:
        return {
            "issue": "Potentially Weak Mode of Operation",
            "description": f"{mode_of_operation} mode can be secure if properly implemented, but may be vulnerable to certain attacks. Prefer authenticated modes like GCM or CCM.",
            "severity": "Medium",
            "endpoint": domain
        }
    elif mode_of_operation in ['GCM', 'CCM']:
        return {
            "issue": "Secure Mode of Operation",
            "description": f"{mode_of_operation} mode provides both encryption and integrity protection and is recommended for most use cases.",
            "severity": "Informational",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown Mode of Operation",
            "description": f"Mode of operation {mode_of_operation} is not recognized or not commonly used.",
            "severity": "Medium",
            "endpoint": domain
        }
