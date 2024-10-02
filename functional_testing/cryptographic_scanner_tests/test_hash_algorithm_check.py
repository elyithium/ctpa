import unittest
from ...server.scanner.cryptographic_scanner.domain_checks.hash_algorithm_check import check_hash_algorithm

class TestHashAlgorithmCheck(unittest.TestCase):

    def test_secure_hash(self):
        result = check_hash_algorithm('SHA-256')
        self.assertTrue(result['is_secure'], "SHA-256 should be recognized as secure")

    def test_insecure_hash(self):
        result = check_hash_algorithm('MD5')
        self.assertFalse(result['is_secure'], "MD5 should be flagged as insecure")

    def test_unknown_hash(self):
        result = check_hash_algorithm('UnknownHash')
        self.assertIsNone(result['is_secure'], "Unknown hash algorithms should return None")

if __name__ == '__main__':
    unittest.main()
