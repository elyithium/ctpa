import OpenSSL
from datetime import datetime

# Check for Expired Certificates
def check_protocol_certificate(cert, domain):
    try:
        # Get the 'notAfter' date from the certificate object (decoded)
        not_after = cert.get_notAfter().decode('ascii')
        # Convert the 'notAfter' field to a datetime object
        not_after_dt = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')

        # Get the current time in UTC
        current_time = datetime.utcnow()

        # Check if the certificate has expired
        if not_after_dt < current_time:
            return {
                "issue": "SSL Certificate",
                "description": f"SSL certificate is expired (Expired on {not_after_dt}).",
                "severity": "High",
                "endpoint": domain
            }
        return {
            "issue": "SSL Certificate",
            "description": f"SSL certificate is valid (Valid until {not_after_dt}).",
            "severity": "Informational",
            "endpoint": domain
        }
    except Exception as e:
        return {
            "issue": "SSL Certificate",
            "description": f"SSL certificate could not be validated: {str(e)}",
            "severity": "High",
            "endpoint": domain
        }
