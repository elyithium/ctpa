import unittest

from scanner.cryptographic_scanner.domain_checks.hash_algorithm_check import check_hash_algorithm

class TestHashAlgorithmCheck(unittest.TestCase):

    def test_secure_hash(self):
        result = check_hash_algorithm('SHA256')
        self.assertEqual(result['issue'], "Strong MAC Algorithm", "SHA-256 should be recognized as a strong MAC algorithm")
        self.assertEqual(result['severity'], "Informational", "SHA-256 should be categorized as Informational severity")

    def test_insecure_hash(self):
        result = check_hash_algorithm('MD5')
        self.assertEqual(result['issue'], "Weak MAC Algorithm", "MD5 should be flagged as a weak MAC algorithm")
        self.assertEqual(result['severity'], "Medium", "MD5 should be categorized as Medium severity")

    def test_unknown_hash(self):
        result = check_hash_algorithm('UnknownHash')
        self.assertEqual(result['issue'], "Unknown MAC Algorithm", "Unknown hash algorithms should return 'Unknown MAC Algorithm'")
        self.assertEqual(result['severity'], "Medium", "Unknown hash algorithms should have Medium severity")


if __name__ == '__main__':
    unittest.main()
