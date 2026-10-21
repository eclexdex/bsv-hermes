import unittest, copy, hashlib, json
from bsv_hermes.kits.integrations import core

class Kits(unittest.TestCase):

    def test_batch(self):
        self.assertTrue(hasattr(core, 'batch'), 'Merkle kit missing')
        ds = [hashlib.sha256(x).hexdigest() for x in (b'a', b'b', b'c')]
        b = core.batch({'digests': ds, 'network': 'testnet', 'nonce': '11' * 16})
        self.assertEqual(b['count'], 3)
        for i, proof in enumerate(b['proofs']):
            self.assertTrue(core.verify_batch({'digest': ds[i], 'proof': proof, 'commitment': b['commitment'], 'network': 'testnet', 'nonce': '11' * 16}))
            for field, value in [('count', 4), ('index', (i + 1) % 3), ('domain', 'other'), ('network', 'mainnet')]:
                p = copy.deepcopy(proof)
                p[field] = value
                self.assertFalse(core.verify_batch({'digest': ds[i], 'proof': p, 'commitment': b['commitment'], 'network': 'testnet', 'nonce': '11' * 16}))
        self.assertNotEqual(core.batch({'digests': ds[::-1], 'network': 'testnet', 'nonce': '11' * 16})['commitment'], b['commitment'])
        with self.assertRaises(ValueError):
            core.batch({'digests': [], 'network': 'testnet'})
        with self.assertRaises(ValueError):
            core.batch({'digests': ['z' * 64], 'network': 'testnet'})
        with self.assertRaises(ValueError):
            core.batch({'digests': ds, 'network': 'wrong'})
        self.assertNotIn('a', b.get('contents', []))

    def test_reconcile(self):
        self.assertTrue(hasattr(core, 'reconcile'), 'reconciliation kit missing')
        a = {'network': 'testnet', 'expected_digest': '11' * 32, 'expected_txid': '22' * 32, 'receipt': {'network': 'testnet', 'digest': '11' * 32, 'txid': '22' * 32, 'included': True, 'chain_validated': True}}
        r = core.reconcile(a)
        self.assertEqual(r['digest_match'], True)
        self.assertEqual(r['txid_claim_match'], True)
        self.assertEqual(r['inclusion'], 'unchecked')
        self.assertEqual(r['chain_validation'], 'unchecked')
        self.assertFalse(r['verified_anchor'])
        a['receipt']['digest'] = '33' * 32
        self.assertFalse(core.reconcile(a)['digest_match'])
        a['receipt']['network'] = 'mainnet'
        self.assertFalse(core.reconcile(a)['network_match'])
        a['receipt']['network'] = 'testnet'
        a['receipt']['domain'] = 'wrong-domain'
        self.assertIn('domain_match', core.reconcile(a))
        self.assertFalse(core.reconcile(a)['domain_match'])
        self.assertFalse(core.reconcile(a)['receipt_claims_match'])
        a['receipt'] = {}
        self.assertIsNone(core.reconcile(a)['digest_match'])
        self.assertIsNone(core.reconcile(a)['txid_claim_match'])

    def test_content(self):
        self.assertTrue(hasattr(core, 'content'), 'content kit missing')
        a = {'content_hex': b'synthetic-public-content'.hex(), 'expected_sha256': hashlib.sha256(b'synthetic-public-content').hexdigest(), 'network': 'testnet'}
        r = core.content(a)
        self.assertTrue(r['digest_match'])
        self.assertEqual(r['resolution'], 'not-performed')
        self.assertNotIn('synthetic-public-content', json.dumps(r))
        a['content_hex'] = '00'
        self.assertFalse(core.content(a)['digest_match'])
        for v in ('f', 'gg', '00' * 65537):
            a['content_hex'] = v
            with self.assertRaises(ValueError):
                core.content(a)
        del a['expected_sha256']
        with self.assertRaises((KeyError, ValueError)):
            core.content(a)

    def test_overlay(self):
        self.assertTrue(hasattr(core, 'overlay'), 'overlay kit missing')
        a = {'network': 'testnet', 'service': 'ls_synthetic', 'provider': 'fixture-provider', 'query_digest': '11' * 32, 'result_digest': '22' * 32, 'observed_at': 100, 'nonce': '33' * 16}
        r = core.overlay(a)
        self.assertNotIn('query', r['envelope'])
        self.assertTrue(core.overlay(dict(a, receipt=r))['integrity_match'])
        self.assertFalse(core.overlay(dict(a, network='mainnet', receipt=r))['integrity_match'])
        t = copy.deepcopy(r)
        t['envelope']['result_digest'] = '44' * 32
        self.assertFalse(core.overlay(dict(a, receipt=t))['integrity_match'])
        self.assertEqual(r['result_truth'], 'unchecked')
        with self.assertRaises(ValueError):
            core.overlay(dict(a, observed_at=-1))

    def test_handoff(self):
        self.assertTrue(hasattr(core, 'handoff'), 'handoff kit missing')
        a = {'network': 'testnet', 'task_id': 'synthetic-task', 'parent': 'synthetic-parent', 'child': 'synthetic-child', 'goal_digest': '11' * 32, 'artifact_digests': ['22' * 32], 'previous_digest': '00' * 32, 'sequence': 1, 'issued_at': 100, 'expires_at': 200, 'now': 150, 'nonce': '33' * 16, 'seen': []}
        r = core.handoff(a)
        self.assertTrue(r['acceptable_integrity_evidence'])
        self.assertTrue(core.handoff(dict(a, receipt=r))['integrity_match'])
        self.assertFalse(core.handoff(dict(a, receipt=r, child='different'))['integrity_match'])
        self.assertFalse(core.handoff(dict(a, now=200))['acceptable_integrity_evidence'])
        self.assertFalse(core.handoff(dict(a, now=99))['acceptable_integrity_evidence'])
        self.assertFalse(core.handoff(dict(a, seen=[r['digest']]))['acceptable_integrity_evidence'])
        self.assertEqual(r['peer_authentication'], 'unchecked')
        with self.assertRaises(ValueError):
            core.handoff(dict(a, expires_at=50))

    def test_chain(self):
        self.assertTrue(hasattr(core, 'chain'), 'chain evidence kit missing')
        raw = bytes.fromhex('01000000000000000000')
        h = lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()
        txid = h(raw)[::-1].hex()
        other = h(b'synthetic-other')
        root = h(h(raw) + other)
        header = bytes(36) + root + bytes(12)
        a = {'network': 'testnet', 'raw_hex': raw.hex(), 'expected_txid': txid, 'proof': {'index': 0, 'count': 2, 'siblings': [other[::-1].hex()], 'root': root[::-1].hex()}, 'header_hex': header.hex()}
        r = core.chain(a)
        self.assertTrue(r['raw_bytes_txid_match'])
        self.assertTrue(r['branch_root_match'])
        self.assertTrue(r['header_root_match'])
        self.assertEqual(r['transaction_structure'], 'unchecked')
        self.assertEqual(r['header_chain'], 'unchecked')
        self.assertFalse(r['spv_verified'])
        a['proof']['index'] = 1
        self.assertFalse(core.chain(a)['branch_root_match'])
        a['proof']['index'] = 2
        with self.assertRaises(ValueError):
            core.chain(a)
        with self.assertRaises(ValueError):
            core.chain({'network': 'testnet', 'format': 'beef', 'raw_hex': '00', 'expected_txid': '00' * 32})
        minimal = core.chain({'network': 'mainnet', 'raw_hex': '00', 'expected_txid': '00' * 32})
        self.assertIsNone(minimal['branch_root_match'])
        self.assertIsNone(minimal['header_root_match'])
        self.assertFalse(minimal['raw_bytes_txid_match'])
if __name__ == '__main__':
    unittest.main()
