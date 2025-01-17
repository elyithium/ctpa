import ssl
import socket
import requests
from urllib.parse import urlparse

from .domain_checks import (
    check_security_defaults,
    check_protocol_certificate,
    check_key_exchange,
    check_encryption_algorithm,
    check_perfect_forward_secrecy,
    check_hash_algorithm,
    check_tls_downgrade_protection,
    check_public_key_length,
    check_authentication_algorithm,
    check_mode_of_operation
)


from .endpoint_checks import (
	check_encoding_usage,
	check_message_integrity_and_signatures
)

from .utils import get_ssl_certificate, get_public_key_length, load_certificate

##########################################
# 	Cryptographic Failures Scanner	     #
##########################################
#   Domain-Wide:
#   1. Default Protocols
#   2. Certificate
#   3. Key Exchange
#   4. Encryption
#   5. MAC Algo
#   6. PFS
#   7. Public Key Length
#   8. TLS Downgrade Protection
#
#   Endpoint-Specific
#   9. Encoding
#   10. Hashing
#   11. Signatures
###########################################

##############################
# Start of Domain Checks     #
##############################

def scan_cryptographic_failures_domain(domain):
    parsed_url = urlparse(domain)
    domain = parsed_url.hostname or parsed_url.path
    results = []

    # Check if the connection is using HTTPS
    if parsed_url.scheme != "https":
        results.append({
            "issue": "Insecure Data Transmission",
            "description": "The connection is not using HTTPS.",
            "severity": "High",
            "endpoint": domain
        })
        return results

    # Create TCP connection
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:

				# Cipher suite info
                cipher_suite, tls_version, key_length = ssl_sock.cipher()
                key_exchange, authentication, encryption_algorithm, mode_of_operation, hash_algorithm = split_cipher_suite(cipher_suite)
                protocol_version = ssl_sock.version()  # TLS version
                print(key_exchange, authentication, encryption_algorithm, mode_of_operation, hash_algorithm)
                # Get certificate details
                cert_bin = get_ssl_certificate(domain)
                cert = load_certificate(cert_bin)
                key_size = get_public_key_length(cert)


                # Domain-Wide Checks into results []
                # Expired Cert Check
                cert_result = check_protocol_certificate(cert, domain)
                results.append(cert_result)

                # Protocol Check
                protocol_result =  check_security_defaults(protocol_version, domain)
                results.append(protocol_result)

                # Key Checks
                key_exchange_result = check_key_exchange(key_exchange, domain)
                results.append(key_exchange_result)

                pfs_result = check_perfect_forward_secrecy(key_exchange, domain)
                results.append(pfs_result)

                key_length_result = check_public_key_length(key_size, domain)
                results.append(key_length_result)

				# Auth Check
                auth_result = check_authentication_algorithm(authentication, domain)
                results.append(auth_result)

                # Encryption Check
                encryption_algo_result = check_encryption_algorithm(encryption_algorithm, domain)
                results.append(encryption_algo_result)

				# Mode of operation Check
                mode_of_operation_result = check_mode_of_operation(mode_of_operation, domain)
                results.append(mode_of_operation_result)

                # Hash Check
                hash_algo_result = check_hash_algorithm(hash_algorithm, domain)
                results.append(hash_algo_result)

                # TLS Downgrade Check
                tls_downgrade_result = check_tls_downgrade_protection(domain)
                results.append(tls_downgrade_result)

                return results

    except Exception as e:
        return [{
            "issue": "SSL/TLS Protocol",
            "description": f"Error establishing SSL/TLS connection: {str(e)}",
            "severity": "High",
            "details": f"Could not verify SSL/TLS protocols for {domain}."
        }]

##############################
# Start of Endpoint Checks   #
##############################

def scan_cryptographic_failures_endpoint(endpoint, params):
    try:
        # Data Gathering
        results = []
        response = requests.post(endpoint, params)
        content = response.text

        # Endpoint Checks
        #print('1')
        encoding_result = check_encoding_usage(content, endpoint)
        results.append(encoding_result)

        #print('3')
        signatures_result = check_message_integrity_and_signatures(content, endpoint)
        results.append(signatures_result)

        return results

    except Exception as e:
        return {"issue": "Request Failed", "details": str(e)}

def split_cipher_suite(cipher_suite):
    # Step 1: Split the cipher suite string by dashes
    parts = cipher_suite.split('-')

    # Step 2: Initialize the components
    key_exchange = None
    authentication = None
    encryption_algorithm = None
    mode_of_operation = None
    hash_algorithm = None

    # Define known elements
    key_exchange_algorithms = ['ECDHE', 'DHE', 'DH']
    authentication_algorithms = ['RSA', 'ECDSA', 'DSA']
    encryption_algorithms = ['AES', 'DES', 'ChaCha20', 'RC4']
    modes_of_operation = ['GCM', 'CBC', 'CCM']
    hash_algorithms = ['SHA256', 'SHA384', 'SHA512', 'MD5']

    # Step 3: Parse the cipher suite
    for part in parts:
        # Check for key exchange algorithm
        if part in key_exchange_algorithms and key_exchange is None:
            key_exchange = part
        # Check for authentication algorithm
        elif part in authentication_algorithms and authentication is None:
            authentication = part
        # Check for encryption algorithm
        elif part in encryption_algorithms and encryption_algorithm is None:
            encryption_algorithm = part
        # Check for mode of operation (e.g., GCM or CBC)
        elif part in modes_of_operation and mode_of_operation is None:
            mode_of_operation = part
        # Check for MAC algorithm
        elif part in hash_algorithms and hash_algorithm is None:
            hash_algorithm = part

    # Handle cases where encryption_algorithm is missing (e.g., ECDHE-RSA-GCM-SHA256)
    if encryption_algorithm is None and mode_of_operation is not None:
        encryption_algorithm = parts[2]  # Assume the second part before the mode is the encryption algorithm

    return (key_exchange or 'Unknown'), (authentication or 'Unknown'), (encryption_algorithm or 'Unknown'), (mode_of_operation or 'Unknown'), (hash_algorithm or 'Unknown')
