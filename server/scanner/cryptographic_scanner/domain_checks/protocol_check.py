# Check for security defaults TLS/SSL
def check_security_defaults(protocol_version, domain="N/A"):
    secure_protocols = ['TLSv1.2', 'TLSv1.3']
    deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

    if protocol_version in secure_protocols:
        return {
            "issue": "SSL/TLS Protocol",
            "description": f"{protocol_version} is secure and supported.",
            "severity": "Informational",
            "details": f"{protocol_version} is recommended for use.",
            "endpoint": domain
        }
    elif protocol_version in deprecated_protocols:
        return {
            "issue": "SSL/TLS Protocol",
            "description": f"{protocol_version} is deprecated or insecure.",
            "severity": "High",
            "details": f"{protocol_version} is no longer considered secure.",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown SSL/TLS Protocol",
            "description": f"Unknown or unsupported protocol: {protocol_version}.",
            "severity": "Medium",
            "details": f"Protocol version {protocol_version} is not recognized.",
            "endpoint": domain
        }
