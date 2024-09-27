def check_authentication_algorithm(auth_algo, domain):
    if auth_algo == 'RSA':
        return {
            "issue": "Weak Authentication Algorithm",
            "description": "RSA is widely used but can be considered weak for authentication in modern contexts.",
            "severity": "Medium",
            "endpoint": domain
        }
    elif auth_algo == 'ECDSA':
        return {
            "issue": "Strong Authentication Algorithm",
            "description": "ECDSA provides strong authentication and is preferred in modern TLS configurations.",
            "severity": "Informational",
            "endpoint": domain
        }
    elif auth_algo == 'DSA':
        return {
            "issue": "Deprecated Authentication Algorithm",
            "description": "DSA is deprecated and not recommended for use in TLS configurations.",
            "severity": "High",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown Authentication Algorithm",
            "description": f"Authentication algorithm {auth_algo} is not recognized or not commonly used.",
            "severity": "Medium",
            "endpoint": domain
        }
