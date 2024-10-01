import unittest
from server.scanner.cryptographic_scanner.endpoint_checks.check_encoding_usage import check_encoding_usage

class TestCheckEncodingUsage(unittest.TestCase):

    def test_valid_encoding(self):
        # Assuming the function returns a dict with 'is_secure'
        result = check_encoding_usage('base64')
        self.assertTrue(result['is_secure'], "Base64 encoding should be secure")

    def test_insecure_encoding(self):
        # Assuming some encoding methods could be insecure
        result = check_encoding_usage('rot13')
        self.assertFalse(result['is_secure'], "ROT13 should be flagged as insecure")

    def test_unknown_encoding(self):
        result = check_encoding_usage('unknownEncoding')
        self.assertIsNone(result.get('is_secure'), "Unknown encodings should return None or equivalent")

if __name__ == '__main__':
    unittest.main()
