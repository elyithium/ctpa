import unittest
from datetime import datetime
from scanner.cryptographic_scanner.domain_checks.certificate_check import check_protocol_certificate

class TestCertificateCheck(unittest.TestCase):

    class FakeCert:
        def get_notAfter(self):
            return b'20230101000000Z'  # Mocking a date in the past

    def test_expired_certificate(self):
        result = check_protocol_certificate(self.FakeCert(), "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
