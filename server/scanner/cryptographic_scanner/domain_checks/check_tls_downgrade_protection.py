import ssl
import socket

# Check TLS Downgrade Protection (Fallback SCSV)
def check_tls_downgrade_protection(domain="N/A"):
    try:
        # Create a context with modern TLS protocols
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # Modern TLS protocols (TLS 1.2 and TLS 1.3)
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disallow old protocols

        # Set a valid cipher suite along with TLS_FALLBACK_SCSV
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:TLS_FALLBACK_SCSV')

        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                # If connection is successful without error, Fallback SCSV might not be supported
                return {
                    "issue": "TLS Downgrade Protection",
                    "description": "Server does not support TLS Fallback SCSV (downgrade protection).",
                    "severity": "High",
                    "endpoint": domain
                }

    except ssl.SSLError as e:
        if 'inappropriate fallback' in str(e):
            # Server supports TLS Fallback SCSV
            return {
                "issue": "TLS Downgrade Protection",
                "description": "Server supports TLS Fallback SCSV (downgrade protection).",
                "severity": "Informational",
                "endpoint": domain
            }
        else:
            # Handle other SSL errors
            return {
                "issue": "TLS Downgrade Protection",
                "description": f"Error during TLS downgrade protection check: {str(e)}",
                "severity": "High",
                "endpoint": domain
            }
