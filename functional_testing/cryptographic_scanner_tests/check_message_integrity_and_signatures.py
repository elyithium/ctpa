import unittest
from ...server.scanner.cryptographic_scanner.endpoint_checks.check_message_integrity_and_signatures import check_message_integrity_and_signatures

class TestCheckMessageIntegrity(unittest.TestCase):

    def test_valid_signature(self):
        result = check_message_integrity_and_signatures('valid_signed_message')
        self.assertTrue(result['is_secure'], "Messages with valid signatures should be secure")

    def test_invalid_signature(self):
        result = check_message_integrity_and_signatures('tampered_message')
        self.assertFalse(result['is_secure'], "Messages with tampered signatures should not be secure")

    def test_missing_signature(self):
        result = check_message_integrity_and_signatures('unsigned_message')
        self.assertIsNone(result.get('is_secure'), "Messages without signatures should return None or equivalent")

if __name__ == '__main__':
    unittest.main()
