import re

# Check if digital signatures are used properly
def check_message_integrity_and_signatures(data, endpoint):
    # Regular expressions to detect potential digital signatures and their components
    rsa_pattern = re.compile(r'\b(rsa|rsa\-signature)\b', re.IGNORECASE)
    ecdsa_pattern = re.compile(r'\b(ecdsa|ecdsa\-signature)\b', re.IGNORECASE)
    signature_pattern = re.compile(r'\bsignature\b', re.IGNORECASE)
    public_key_pattern = re.compile(r'\b(public\skey|pubkey)\b', re.IGNORECASE)
    signed_data_pattern = re.compile(r'\b(signed\sdata|signing)\b', re.IGNORECASE)

    # Flags to track if all necessary components are present
    has_rsa = bool(rsa_pattern.search(data))
    has_ecdsa = bool(ecdsa_pattern.search(data))
    has_signature = bool(signature_pattern.search(data))
    has_public_key = bool(public_key_pattern.search(data))
    has_signed_data = bool(signed_data_pattern.search(data))

    # Check for proper use of RSA or ECDSA with all necessary components
    if (has_rsa or has_ecdsa) and has_signature and has_public_key and has_signed_data:
        return {
            "issue": "Digital Signature",
            "description": "Detected proper use of digital signatures (RSA, ECDSA) with all necessary components.",
            "severity": "Informational",
            "details": {
                "RSA Used": has_rsa,
                "ECDSA Used": has_ecdsa,
                "Signature Present": has_signature,
                "Public Key Present": has_public_key,
                "Signed Data Present": has_signed_data
            },
            "endpoint": endpoint
        }

    # If RSA/ECDSA is found but missing components
    if (has_rsa or has_ecdsa):
        missing_components = []
        if not has_signature:
            missing_components.append("Signature")
        if not has_public_key:
            missing_components.append("Public Key")
        if not has_signed_data:
            missing_components.append("Signed Data")

        return {
            "issue": "Digital Signature",
            "description": f"Detected usage of {'RSA' if has_rsa else 'ECDSA'} but missing necessary components: {', '.join(missing_components)}.",
            "severity": "Medium",
            "details": {
                "RSA Used": has_rsa,
                "ECDSA Used": has_ecdsa,
                "Signature Present": has_signature,
                "Public Key Present": has_public_key,
                "Signed Data Present": has_signed_data
            },
            "endpoint": endpoint
        }

    # If no digital signature-related data is found
    return {
        "issue": "Digital Signature",
        "description": "No digital signature detected or missing key components for proper usage.",
        "severity": "High",
        "details": {
            "RSA Used": has_rsa,
            "ECDSA Used": has_ecdsa,
            "Signature Present": has_signature,
            "Public Key Present": has_public_key,
            "Signed Data Present": has_signed_data
        },
        "endpoint": endpoint
    }
