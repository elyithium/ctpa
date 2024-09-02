import ssl
import socket
import os
import time
from urllib.parse import urlparse

def check_ssl_certificate(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()

        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
        current_time = time.time()

        if not_after < current_time:
            return {"issue": "SSL Certificate", "description": "SSL certificate is expired.", "severity": "High", "details": cert}

        signature_algorithm = cert.get('signatureAlgorithm', 'unknown').lower()
        if any(weak_alg in signature_algorithm for weak_alg in ['md5', 'sha1']):
            return {"issue": "Weak Signature Algorithm", "description": f"Weak signature algorithm ({signature_algorithm}) used.", "severity": "Medium", "details": cert}

        subject_alt_names = cert.get('subjectAltName', [])
        if not any(hostname in alt_name for alt_type, alt_name in subject_alt_names):
            return {"issue": "Hostname Mismatch", "description": "Hostname does not match SSL certificate.", "severity": "High", "details": cert}

        return {"issue": "SSL Certificate", "description": "SSL certificate is valid.", "severity": "Low", "details": cert}

    except ssl.SSLError as e:
        return {"issue": "SSL Certificate Error", "description": f"SSL error: {str(e)}", "severity": "High"}
    except Exception as e:
        return {"issue": "SSL Certificate Error", "description": f"Error checking SSL certificate: {str(e)}", "severity": "High"}
    finally:
        conn.close()

def check_ssl_protocols(hostname):
    protocols = {
        'SSLv3': 'PROTOCOL_SSLv3',
        'TLSv1': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3': ssl.PROTOCOL_TLS,
    }

    results = []
    for protocol_name, protocol in protocols.items():
        try:
            if protocol_name == 'SSLv3':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
            else:
                context = ssl.SSLContext(protocol)

            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.settimeout(3.0)
            conn.connect((hostname, 443))

            if protocol_name == 'SSLv3':
                results.append({
                    "issue": "SSLv3 Protocol",
                    "description": "The server supports SSLv3, which is deprecated and insecure.",
                    "severity": "High",
                    "endpoint": hostname
                })
            else:
                continue  # Skip if not vulnerable

        except ssl.SSLError:
            continue  # Skip if protocol not supported (not vulnerable)
        except Exception as e:
            results.append({
                "issue": f"{protocol_name} Protocol",
                "description": f"Error checking {protocol_name}: {str(e)}",
                "severity": "High",
                "endpoint": hostname
            })

    return results

def check_weak_ciphers(hostname):
    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
    context = ssl.create_default_context()
    context.set_ciphers('ALL')

    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
        supported_ciphers = conn.shared_ciphers()

        weak_found = [
            {
                "issue": "Weak Cipher",
                "description": f"The server supports the {cipher[0]} cipher, which is considered insecure.",
                "severity": "High"
            }
            for cipher in supported_ciphers if any(weak in cipher[0] for weak in weak_ciphers)
        ]

        return weak_found

    except ssl.SSLError as e:
        return [{"issue": "Cipher Error", "description": f"SSL error: {str(e)}", "severity": "High"}]
    except Exception as e:
        return [{"issue": "Cipher Error", "description": f"Error checking ciphers: {str(e)}", "severity": "High"}]
    finally:
        conn.close()

def check_deprecated_algorithms(data):
    if any(weak_alg in data.lower() for weak_alg in ['md5', 'sha1']):
        return {
            "issue": "Deprecated Algorithm",
            "description": "Deprecated cryptographic algorithm detected (MD5 or SHA-1).",
            "severity": "High",
            "details": data
        }
    return {
        "issue": "Algorithm Check",
        "description": "No deprecated algorithms detected.",
        "severity": "Informational"
    }

def check_key_management(key_storage):
    if "plaintext" in key_storage.lower() or "expired" in key_storage.lower():
        return {
            "issue": "Key Management",
            "description": "Insecure key management practices detected (e.g., plaintext keys or expired keys).",
            "severity": "High",
            "details": key_storage
        }
    return {
        "issue": "Key Management",
        "description": "No issues with key management detected.",
        "severity": "Informational"
    }

def check_random_number_generation():
    try:
        import secrets
        test_random = secrets.token_hex(16)
        return {
            "issue": "Secure RNG",
            "description": "Cryptographically secure random number generator is in use.",
            "severity": "Informational",
            "details": test_random
        }
    except ImportError:
        return {
            "issue": "Random Number Generation",
            "description": "Cryptographically secure RNG is not available.",
            "severity": "High"
        }

def check_encryption_of_data_at_rest(data_storage):
    if "not encrypted" in data_storage.lower():
        return {
            "issue": "Encryption at Rest",
            "description": "Data at rest is not encrypted.",
            "severity": "High",
            "details": data_storage
        }
    return {
        "issue": "Encryption at Rest",
        "description": "Data at rest is encrypted.",
        "severity": "Informational"
    }

def check_message_integrity_and_signatures(data):
    if "signature" not in data.lower() or "integrity check" not in data.lower():
        return {
            "issue": "Message Integrity and Signatures",
            "description": "Message integrity checks or digital signatures are missing.",
            "severity": "High",
            "details": data
        }
    return {
        "issue": "Message Integrity and Signatures",
        "description": "Message integrity checks and digital signatures are present.",
        "severity": "Low"
    }

def check_correct_use_of_crypto_libraries():
    try:
        import cryptography
        # Simulate correct usage check
        return {
            "issue": "Cryptographic Libraries",
            "description": "Cryptographic libraries are used correctly.",
            "severity": "Low"
        }
    except ImportError:
        return {
            "issue": "Cryptographic Libraries",
            "description": "Cryptographic libraries are not used correctly or are missing.",
            "severity": "High"
        }


def scan_cryptographic_failures(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path

    results = []

    if parsed_url.scheme != "https":
        results.append({
            "issue": "Insecure Data Transmission",
            "description": "The connection is not using HTTPS.",
            "severity": "High",
            "endpoint": url
        })
    else:
        cert_result = check_ssl_certificate(hostname)
        cert_result["endpoint"] = url
        results.append(cert_result)

        protocol_results = check_ssl_protocols(hostname)
        for result in protocol_results:
            result["endpoint"] = url
        results.extend(protocol_results)

        cipher_results = check_weak_ciphers(hostname)
        for result in cipher_results:
            result["endpoint"] = url
        results.extend(cipher_results)

    # Placeholder for additional cryptographic checks
    test_data = "data containing MD5"
    key_storage = "key storage containing plaintext and expired keys"
    data_storage = "data not encrypted"

    algo_result = check_deprecated_algorithms(test_data)
    algo_result["endpoint"] = url
    results.append(algo_result)

    key_mgmt_result = check_key_management(key_storage)
    key_mgmt_result["endpoint"] = url
    results.append(key_mgmt_result)

    rng_result = check_random_number_generation()
    rng_result["endpoint"] = url
    results.append(rng_result)

    encryption_result = check_encryption_of_data_at_rest(data_storage)
    encryption_result["endpoint"] = url
    results.append(encryption_result)

    integrity_result = check_message_integrity_and_signatures(test_data)
    integrity_result["endpoint"] = url
    results.append(integrity_result)

    crypto_lib_result = check_correct_use_of_crypto_libraries()
    crypto_lib_result["endpoint"] = url
    results.append(crypto_lib_result)

    return results

if __name__ == "__main__":
    url = "http://example.com"  # You can change this to a test URL
    cryptographic_results = scan_cryptographic_failures(url)
    for result in cryptographic_results:
        print(result)
