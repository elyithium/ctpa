import unittest
from server.scanner.cryptographic_scanner.domain_checks.key_exchange_check import key_exchange_check

class TestKeyExchangeCheck(unittest.TestCase):

    def test_secure_key_exchange(self):
        result = key_exchange_check('ECDHE')
        self.assertTrue(result['is_secure'], "ECDHE should be recognized as a secure key exchange algorithm")

    def test_insecure_key_exchange(self):
        result = key_exchange_check('RSA')
        self.assertFalse(result['is_secure'], "RSA key exchange should be flagged as insecure in certain configurations")

if __name__ == '__main__':
    unittest.main()
