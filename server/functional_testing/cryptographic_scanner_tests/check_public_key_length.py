import unittest
from scanner.cryptographic_scanner.domain_checks.check_public_key_length import check_public_key_length

class TestCheckPublicKeyLength(unittest.TestCase):

    def test_valid_key_length(self):
        result = check_public_key_length(2048, "example.com")
        self.assertEqual(result["severity"], "Informational")
        self.assertIn("sufficient", result["description"])

    def test_invalid_key_length(self):
        result = check_public_key_length(1024, "example.com")
        self.assertEqual(result["severity"], "High")
        self.assertIn("too short", result["description"])

if __name__ == '__main__':
    unittest.main()
