import unittest
from server.scanner.cryptographic_scanner.domain_checks.check_perfect_forward_secrecy import check_perfect_forward_secrecy

class TestCheckPerfectForwardSecrecy(unittest.TestCase):

    def test_pfs_enabled(self):
        result = check_perfect_forward_secrecy('ECDHE')
        self.assertTrue(result['is_secure'], "ECDHE should support Perfect Forward Secrecy")

    def test_pfs_not_enabled(self):
        result = check_perfect_forward_secrecy('RSA')
        self.assertFalse(result['is_secure'], "RSA should not support Perfect Forward Secrecy")

if __name__ == '__main__':
    unittest.main()
