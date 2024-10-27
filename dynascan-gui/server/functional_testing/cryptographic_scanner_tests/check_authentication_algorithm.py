import unittest
from scanner.cryptographic_scanner.domain_checks.check_authentication_algorithm import check_authentication_algorithm

class TestCheckAuthenticationAlgorithm(unittest.TestCase):

    def test_strong_algorithm(self):
        result = check_authentication_algorithm("ECDSA", "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_deprecated_algorithm(self):
        result = check_authentication_algorithm("DSA", "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
