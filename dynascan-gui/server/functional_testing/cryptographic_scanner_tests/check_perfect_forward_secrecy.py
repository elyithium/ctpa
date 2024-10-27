import unittest
from scanner.cryptographic_scanner.domain_checks.check_perfect_forward_secrecy import check_perfect_forward_secrecy

class TestCheckPerfectForwardSecrecy(unittest.TestCase):

    def test_supported_cipher(self):
        result = check_perfect_forward_secrecy("ECDHE-RSA-AES128-GCM-SHA256", "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_not_supported_cipher(self):
        result = check_perfect_forward_secrecy("AES128-SHA", "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
