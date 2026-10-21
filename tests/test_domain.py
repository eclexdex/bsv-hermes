import hashlib
import unittest

try:
    from bsv_hermes import domain
except ImportError:
    domain = None


class CommitmentTests(unittest.TestCase):
    def test_empty_text_literal_commitment(self):
        self.assertIsNotNone(domain, 'domain implementation missing')
        result = domain.plan_commitment('')
        self.assertEqual(result['locking_script_hex'], '006a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertEqual(result['size_bytes'], 35)
        self.assertEqual(result['status'], {'signed': False, 'paid': False, 'transaction_built': False, 'broadcast': False})

class CommitmentValidationTests(unittest.TestCase):
    def test_utf8_and_limits(self):
        self.assertEqual(domain.plan_commitment('é')['digest_hex'], hashlib.sha256(b'\xc3\xa9').hexdigest())
        for value in (None, True, b'x', 'x' * 4097, '\ud800'):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                domain.plan_commitment(value)
        domain.plan_commitment('x' * 4096)

if __name__ == '__main__':
    unittest.main()
