import hashlib
import unittest
from bsv_hermes import domain

# Original synthetic wire fixture; no chain assertion. Fields independently
# assembled: v1, one null outpoint input, empty script, final sequence,
# one 1000-satoshi OP_TRUE output, locktime zero.
TX = '0100000001' + '00' * 32 + 'ffffffff00ffffffff01e803000000000000015100000000'

class TransactionTests(unittest.TestCase):
    def test_rejects_truncation_noncanonical_and_unsupported(self):
        raw = bytes.fromhex(TX)
        cases = [raw[:i].hex() for i in range(len(raw))]
        cases += [TX + '00', '010000000001', TX[:8] + 'fd0100' + TX[10:],
                  TX[:8] + 'fe01000000' + TX[10:], TX[:8] + 'ff0100000000000000' + TX[10:],
                  TX[:8] + 'fde903', TX[:8] + '00', '00' * 100001,
                  TX[:92] + 'fd1127' + TX[94:]]
        for value in cases:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                domain.inspect_transaction(value)
        for limit in (True, 0, 101, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                domain.inspect_transaction(TX, limit)

    def test_reader_canonical_compact_boundaries(self):
        for wire, expected in [('fc',252), ('fdfd00',253), ('fdffff',65535), ('fe00000100',65536), ('ff0000000001000000',4294967296)]:
            self.assertEqual(domain.Reader(bytes.fromhex(wire)).compact(), expected)
        for wire in ('fd', 'fe0000', 'ff00000000', 'fdfc00', 'feffff0000', 'ffffffffff00000000'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                domain.Reader(bytes.fromhex(wire)).compact()

    def test_counts_display_and_satoshi_integer(self):
        prefix = '0100000001' + '00' * 32 + 'ffffffff00ffffffff'
        tx = prefix + '02' + 'ffffffffffffffff0151' * 2 + '00000000'
        result = domain.inspect_transaction(tx, 1)
        self.assertEqual(result['output_count'], 2)
        self.assertEqual(len(result['outputs']), 1)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['outputs'][0]['satoshis'], 18446744073709551615)
        self.assertIs(type(result['outputs'][0]['satoshis']), int)
        with self.assertRaises(ValueError):
            domain.inspect_transaction(prefix + '00' + '00000000')
        with self.assertRaises(ValueError):
            domain.inspect_transaction(prefix + 'fde903')

    def test_legacy_summary(self):
        self.assertTrue(hasattr(domain, 'inspect_transaction'), 'transaction parser missing')
        result = domain.inspect_transaction(TX)
        self.assertEqual(result['txid'], 'cdb9f8dfefadc40b90a8eb090bcadc4d9a83ad5fbe38645e3e9b2fa234f032de')
        self.assertEqual(result['txid'], hashlib.sha256(hashlib.sha256(bytes.fromhex(TX)).digest()).digest()[::-1].hex())
        self.assertEqual(result['version'], 1)
        self.assertEqual(result['locktime'], 0)
        self.assertEqual(result['input_count'], 1)
        self.assertEqual(result['output_count'], 1)
        self.assertEqual(result['inputs'][0]['previous_txid'], '00' * 32)
        self.assertEqual(result['inputs'][0]['sequence'], 4294967295)
        self.assertEqual(result['outputs'][0]['satoshis'], 1000)
        self.assertEqual(result['outputs'][0]['script_hex'], '51')
        self.assertIsNone(result['fee_satoshis'])
        self.assertFalse(result['consensus_validated'])
