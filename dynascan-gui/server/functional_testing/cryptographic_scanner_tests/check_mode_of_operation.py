import unittest
from scanner.cryptographic_scanner.domain_checks.check_mode_of_operation import check_mode_of_operation

class TestCheckModeOfOperation(unittest.TestCase):

    def test_secure_mode(self):
        result = check_mode_of_operation("GCM", "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_weak_mode(self):
        result = check_mode_of_operation("ECB", "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
