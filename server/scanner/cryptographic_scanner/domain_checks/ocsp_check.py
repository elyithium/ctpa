import socket
import OpenSSL
from OpenSSL import SSL

def check_ocsp_stapling_in_handshake(domain):
    try:
        # Create a new context for TLS and load the CA certificates
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")  # Use the correct path for your system
        context.set_verify(SSL.VERIFY_PEER, callback=None)  # Require peer verification

        # Create a connection using OpenSSL
        sock = socket.create_connection((domain, 443))
        ssl_sock = SSL.Connection(context, sock)
        ssl_sock.set_tlsext_host_name(domain.encode())  # Set SNI (Server Name Indication)
        ssl_sock.set_connect_state()

        print(f"Initiating handshake with {domain}...")
        ssl_sock.do_handshake()
        print(f"Handshake completed with {domain}")

        # Check if OCSP stapling is supported
        ocsp_response = ssl_sock.get_ocsp_response()
        print(f"OCSP Response: {ocsp_response}")

        if ocsp_response:
            return {
                "issue": "OCSP Stapling",
                "description": "OCSP stapling is supported and an OCSP response was received.",
                "severity": "Informational",
                "endpoint": domain
            }
        else:
            return {
                "issue": "OCSP Stapling",
                "description": "OCSP stapling is not supported or no OCSP response was received.",
                "severity": "Medium",
                "endpoint": domain
            }

    except Exception as e:
        return {
            "issue": "OCSP Stapling",
            "description": f"Error checking OCSP stapling in handshake: {str(e)}",
            "severity": "High",
            "endpoint": domain
        }
    finally:
        try:
            ssl_sock.shutdown()
            ssl_sock.close()
        except:
            pass
