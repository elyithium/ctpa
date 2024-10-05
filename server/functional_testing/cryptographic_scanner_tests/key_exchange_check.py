import unittest
from scanner.cryptographic_scanner.domain_checks.key_exchange_check import check_key_exchange

class TestKeyExchangeCheck(unittest.TestCase):

    def test_strong_key_exchange(self):
        result = check_key_exchange("ECDHE", "example.com")
        self.assertEqual(result["severity"], "Informational")

    def test_weak_key_exchange(self):
        result = check_key_exchange("RSA", "example.com")
        self.assertEqual(result["severity"], "High")

if __name__ == '__main__':
    unittest.main()
