import unittest
from server.scanner.cryptographic_scanner.domain_checks.certificate_check import certificate_check

class TestCertificateCheck(unittest.TestCase):

    def test_valid_certificate(self):
        result = certificate_check('valid_cert.pem')
        self.assertTrue(result['is_valid'], "Valid certificates should pass the check")

    def test_expired_certificate(self):
        result = certificate_check('expired_cert.pem')
        self.assertFalse(result['is_valid'], "Expired certificates should fail the check")

    def test_missing_certificate(self):
        result = certificate_check(None)
        self.assertFalse(result['is_valid'], "Missing certificates should return False")

if __name__ == '__main__':
    unittest.main()
