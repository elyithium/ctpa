import ssl
import socket
import OpenSSL

def get_public_key_length(cert):
    try:
        # Get the public key from the certificate
        public_key = cert.get_pubkey()

        # Check if it's an RSA or EC key
        if isinstance(public_key, OpenSSL.crypto.PKey):
            key_size = public_key.bits()
            return key_size
        else:
            return None
    except Exception as e:
        print(f"Error extracting public key: {e}")
        return None

# Establish SSL connection and extract certificate
def get_ssl_certificate(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
            cert_bin = ssl_sock.getpeercert(binary_form=True)
            return cert_bin

def load_certificate(cert_bin):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
    return cert
