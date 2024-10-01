import unittest
from server.scanner.cryptographic_scanner.domain_checks.check_encryption_algorithm import check_encryption_algorithm

class TestCheckEncryptionAlgorithm(unittest.TestCase):

    def test_secure_algorithm(self):
        result = check_encryption_algorithm('AES')
        self.assertTrue(result['is_secure'], "AES should be recognized as a secure algorithm")

    def test_insecure_algorithm(self):
        result = check_encryption_algorithm('DES')
        self.assertFalse(result['is_secure'], "DES should be flagged as insecure")

    def test_unknown_algorithm(self):
        result = check_encryption_algorithm('UnknownAlg')
        self.assertIsNone(result['is_secure'], "Unknown algorithms should return None or equivalent result")

if __name__ == '__main__':
    unittest.main()
