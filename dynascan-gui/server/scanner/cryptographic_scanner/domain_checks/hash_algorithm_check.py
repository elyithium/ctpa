# Check for Strong or Weak Message Authentication Code (MAC) Algorithms
def check_hash_algorithm(hash_algo, domain="N/A"):
    if 'SHA256' in hash_algo or 'SHA384' in hash_algo:
        return {
            "issue": "Strong MAC Algorithm",
            "description": f"{hash_algo} is secure for ensuring message integrity.",
            "severity": "Informational",
            "endpoint": domain
        }
    elif 'SHA1' in hash_algo or 'MD5' in hash_algo:
        return {
            "issue": "Weak MAC Algorithm",
            "description": f"{hash_algo} is deprecated and insecure.",
            "severity": "Medium",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown MAC Algorithm",
            "description": f"MAC algorithm {hash_algo} is not recognized.",
            "severity": "Medium",
            "endpoint": domain
        }
