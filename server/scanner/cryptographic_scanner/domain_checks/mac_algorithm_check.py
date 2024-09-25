# Check for Strong or Weak Message Authentication Code (MAC) Algorithms
def check_mac_algorithm(mac_algo, domain):
    if 'SHA256' in mac_algo or 'SHA384' in mac_algo:
        return {
            "issue": "Strong MAC Algorithm",
            "description": f"{mac_algo} is secure for ensuring message integrity.",
            "severity": "Informational",
            "endpoint": domain
        }
    elif 'SHA1' in mac_algo or 'MD5' in mac_algo:
        return {
            "issue": "Weak MAC Algorithm",
            "description": f"{mac_algo} is deprecated and insecure.",
            "severity": "Medium",
            "endpoint": domain
        }
    else:
        return {
            "issue": "Unknown MAC Algorithm",
            "description": f"MAC algorithm {mac_algo} is not recognized.",
            "severity": "Medium",
            "endpoint": domain
        }
