import unittest
from scanner.cryptographic_scanner.endpoint_checks.check_message_integrity_and_signatures import check_message_integrity_and_signatures

class TestCheckMessageIntegrityAndSignatures(unittest.TestCase):

    def test_proper_usage(self):
        data = "This message contains rsa-signature, a public key, and signed data."
        result = check_message_integrity_and_signatures(data, "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_missing_components(self):
        data = "This message contains rsa but is missing a signature."
        result = check_message_integrity_and_signatures(data, "example.com")
        self.assertEqual(result["severity"], "Medium")
        self.assertIn("missing necessary components", result["description"])

    def test_no_signatures_detected(self):
        data = "This message does not contain any digital signatures."
        result = check_message_integrity_and_signatures(data, "example.com")
        self.assertEqual(result["severity"], "High")
        self.assertIn("No digital signature detected", result["description"])

if __name__ == '__main__':
    unittest.main()
