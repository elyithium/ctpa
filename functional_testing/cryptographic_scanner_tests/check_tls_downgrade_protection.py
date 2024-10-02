import unittest
from ...server.scanner.cryptographic_scanner.domain_checks.check_tls_downgrade_protection import check_tls_downgrade_protection

class TestCheckTLSDowngradeProtection(unittest.TestCase):

    def test_tls_with_downgrade_protection(self):
        result = check_tls_downgrade_protection('TLSv1.2')
        self.assertTrue(result['is_secure'], "TLS v1.2 should have downgrade protection")

    def test_tls_without_downgrade_protection(self):
        result = check_tls_downgrade_protection('SSLv3')
        self.assertFalse(result['is_secure'], "SSLv3 should be flagged as insecure without downgrade protection")

if __name__ == '__main__':
    unittest.main()
