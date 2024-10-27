import unittest
from scanner.cryptographic_scanner.domain_checks.check_encryption_algorithm import check_encryption_algorithm

class TestCheckEncryptionAlgorithm(unittest.TestCase):

    def test_strong_algorithm(self):
        result = check_encryption_algorithm("AES", "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_weak_algorithm(self):
        result = check_encryption_algorithm("RC4", "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
