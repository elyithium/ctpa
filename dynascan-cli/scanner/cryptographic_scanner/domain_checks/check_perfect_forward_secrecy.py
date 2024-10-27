#forward secrecy check
def check_perfect_forward_secrecy(cipher, domain):
    if 'ECDHE' in cipher or 'DHE' in cipher:
        return {
            "issue": "Perfect Forward Secrecy",
            "description": "Cipher suite supports Perfect Forward Secrecy.",
            "severity": "Informational",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Perfect Forward Secrecy",
            "description": "Cipher suite does not support Perfect Forward Secrecy.",
            "severity": "High",
            "endpoint": domain
        }
