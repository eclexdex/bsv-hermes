import copy
import hashlib
import json
import unittest
from pathlib import Path
from bsv_hermes.receipts import batch as b


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.rows = [('r1', b'completed synthetic receipt 1'), ('r2', b'completed synthetic receipt 2'), ('r3', b'completed synthetic receipt 3')]
        self.nonces = ['01'*32, '02'*32, '03'*32]
        self.batch = b.build_batch(self.rows, nonces=self.nonces, export_private_proofs=True)
        self.manifest = self.batch['manifest']

    def test_roundtrip_and_singleton(self):
        for rows, nonces in [(self.rows, self.nonces), (self.rows[:1], self.nonces[:1])]:
            result = b.build_batch(rows, nonces=nonces, export_private_proofs=True)
            for row, proof in zip(rows, result['private_proofs']):
                self.assertTrue(b.verify_proof(proof, expected_commitment=result['manifest']['commitment'], receipt_bytes=row[1]))
            self.assertTrue(b.verify_complete_batch(result['manifest'], rows, nonces=nonces))

    def test_negative_openings(self):
        original = self.batch['private_proofs'][2]
        changes = {'index':0, 'count':2, 'network':'testnet', 'version':'legacy', 'receipt_id':'other', 'receipt_sha256':'00'*32, 'nonce_hex':'ff'*32, 'siblings':[], 'extra':True}
        for key, value in changes.items():
            proof = copy.deepcopy(original)
            proof[key] = value
            self.assertFalse(b.verify_proof(proof, expected_commitment=self.manifest['commitment']), key)
        proof = copy.deepcopy(original)
        proof['siblings'][0] = '00'*32
        self.assertFalse(b.verify_proof(proof, expected_commitment=self.manifest['commitment']))
        self.assertFalse(b.verify_proof(original, expected_commitment='00'*32))
        self.assertFalse(b.verify_proof(original, expected_commitment=self.manifest['commitment'], receipt_bytes=b'tampered'))
        for value in (True, -1, 3, 1.0):
            proof = dict(original, index=value)
            self.assertFalse(b.verify_proof(proof, expected_commitment=self.manifest['commitment']))

    def test_reorder_missing_and_duplicate(self):
        for rows, nonces in [(self.rows[::-1], self.nonces[::-1]), (self.rows[:-1], self.nonces[:-1])]:
            self.assertFalse(b.verify_complete_batch(self.manifest, rows, nonces=nonces))
        for rows, nonces in [(self.rows+[self.rows[0]], self.nonces+['04'*32]), (self.rows, ['01'*32]*3), (self.rows, self.nonces[:-1]), ([], []), (set(), [])]:
            with self.assertRaises(ValueError):
                b.build_batch(rows, nonces=nonces)

    def test_bounds(self):
        for rows, nonces in [([('r', b'')], ['01'*32]), ([('r', b'a'*(b.MAX_RECEIPT_BYTES+1))], ['01'*32]), ([('x',b'a')]*1025, ['01'*32]*1025), ([('bad id',b'a')], ['01'*32])]:
            with self.assertRaises(ValueError):
                b.build_batch(rows, nonces=nonces)
        rows = [('r'+str(i), b'a'*b.MAX_RECEIPT_BYTES) for i in range(9)]
        with self.assertRaises(ValueError):
            b.build_batch(rows, nonces=[format(i,'064x') for i in range(9)])

    def test_privacy_determinism(self):
        self.assertEqual(self.batch, b.build_batch(self.rows, nonces=self.nonces, export_private_proofs=True))
        public = b.build_batch(self.rows, nonces=self.nonces)
        self.assertNotIn('private_proofs', public)
        for value in ('r1', self.nonces[0], b.digest(self.rows[0][1])):
            self.assertNotIn(value, json.dumps(public))
        changed = b.build_batch(self.rows, nonces=['04'*32]+self.nonces[1:])
        self.assertNotEqual(public['manifest']['commitment'], changed['manifest']['commitment'])

    def test_quote_adapter_no_authority(self):
        req = b.commitment_request(self.manifest, workflow_id='synthetic-1')
        text = req['arguments']['text'].encode()
        self.assertEqual(req['expected_commitment_script_hex'], '006a20'+hashlib.sha256(text).hexdigest())
        self.assertNotEqual(req['expected_text_sha256'], self.manifest['root'])
        self.assertEqual(req['approval'], 'absent')
        for field, value in [('root','00'*32), ('network','testnet'), ('version','old')]:
            with self.assertRaises(ValueError):
                b.commitment_request(dict(self.manifest, **{field:value}), workflow_id='synthetic-1')

    def test_independent_single_leaf_oracle(self):
        # Literal preimages, not production canonical/tag helpers.
        leaf_preimage = b'bsv-hermes-receipt-batch/1/leaf\x00' + b'{"nonce_hex":"' + b'01'*32 + b'","receipt_id":"r1","receipt_sha256":"' + hashlib.sha256(self.rows[0][1]).hexdigest().encode() + b'"}'
        root = hashlib.sha256(leaf_preimage).hexdigest()
        preimage = b'bsv-hermes-receipt-batch/1/commitment\x00' + b'{"count":1,"network":"mainnet","root":"' + root.encode() + b'"}'
        expected = hashlib.sha256(preimage).hexdigest()
        actual = b.build_batch(self.rows[:1], nonces=self.nonces[:1])['manifest']
        self.assertEqual(root, actual['root'])
        self.assertEqual(expected, actual['commitment'])

    def test_literal_vector(self):
        vector = json.loads((Path(__file__).parent / 'receipt_vectors/batch.json').read_text())
        self.assertEqual(self.batch, vector['batch'])
        self.assertEqual(b.commitment_request(self.manifest, workflow_id='synthetic-1'), vector['request'])


if __name__ == '__main__':
    unittest.main()
