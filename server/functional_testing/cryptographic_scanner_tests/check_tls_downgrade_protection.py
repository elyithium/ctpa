import unittest
from scanner.cryptographic_scanner.domain_checks.check_tls_downgrade_protection import check_tls_downgrade_protection

class TestTLSDowngradeProtection(unittest.TestCase):

    def test_tls_fallback(self):
        result = check_tls_downgrade_protection("example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
