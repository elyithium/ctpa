import unittest
from ...server.scanner.cryptographic_scanner.domain_checks.check_public_key_length import check_public_key_length

class TestCheckPublicKeyLength(unittest.TestCase):

    def test_valid_key_length(self):
        result = check_public_key_length(2048)
        self.assertTrue(result['is_secure'], "2048-bit key length should be secure")

    def test_insecure_key_length(self):
        result = check_public_key_length(512)
        self.assertFalse(result['is_secure'], "512-bit key length should be flagged as insecure")

if __name__ == '__main__':
    unittest.main()
