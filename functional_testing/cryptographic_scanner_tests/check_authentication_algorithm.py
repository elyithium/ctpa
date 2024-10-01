import unittest
from server.scanner.cryptographic_scanner.domain_checks.check_authentication_algorithm import check_authentication_algorithm

class TestCheckAuthenticationAlgorithm(unittest.TestCase):

    def test_secure_auth_algorithm(self):
        result = check_authentication_algorithm('HMAC')
        self.assertTrue(result['is_secure'], "HMAC should be recognized as a secure algorithm")

    def test_insecure_auth_algorithm(self):
        result = check_authentication_algorithm('MD5')
        self.assertFalse(result['is_secure'], "MD5 should be flagged as insecure for authentication")

    def test_unknown_auth_algorithm(self):
        result = check_authentication_algorithm('UnknownAuthAlg')
        self.assertIsNone(result['is_secure'], "Unknown authentication algorithms should return None or equivalent")

if __name__ == '__main__':
    unittest.main()
