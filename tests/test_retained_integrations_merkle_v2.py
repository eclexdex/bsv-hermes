"""Independent protocol bytes oracle; never derive expected roots via producer/verifier."""
import hashlib
import json
import unittest
from bsv_hermes.kits.integrations import core

class MerkleV2(unittest.TestCase):

    def test_positions_count_and_order_against_independent_bytes(self):
        h = lambda b: hashlib.sha256(b).digest()
        for ds in [['11' * 32, '11' * 32], ['11' * 32, '22' * 32], ['22' * 32, '11' * 32], ['11' * 32] * 3]:
            leaves = [h(b'\x00' + index.to_bytes(4, 'big') + bytes.fromhex(d)) for index, d in enumerate(ds)]
            row = leaves[:]
            while len(row) > 1:
                row = [h(b'\x01' + row[j] + row[min(j + 1, len(row) - 1)]) for j in range(0, len(row), 2)]
            payload = {'domain': 'bsv-hermes/merkle-batch/v1', 'count': len(ds), 'root': row[0].hex(), 'network': 'testnet', 'nonce': '33' * 16}
            expected = h(b'\x02' + json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('ascii')).hex()
            result = core.batch(dict(digests=ds, network='testnet', nonce='33' * 16))
            self.assertEqual(result['commitment'], expected)
            self.assertEqual(result['proofs'][0]['siblings'][0], leaves[1].hex())
            for i, p in enumerate(result['proofs']):
                self.assertEqual(p['index'], i)
                self.assertEqual(p['count'], len(ds))
                self.assertTrue(core.verify_batch(dict(digest=ds[i], proof=p, commitment=expected, network='testnet', nonce='33' * 16)))
if __name__ == '__main__':
    unittest.main()
