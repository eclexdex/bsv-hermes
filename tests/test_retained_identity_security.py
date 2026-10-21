import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from bsv_hermes.kits.identity import core
from bsv_hermes.kits.identity.operations import execute

class SecurityTests(unittest.TestCase):

    def test_receipt_scalar_types_are_binding(self):
        r, _ = core.soul(b'synthetic')
        r['private_nonce'] = 0
        self.assertFalse(core.verify(r, b'synthetic'))

    def test_all_security_fields_and_flags_reject_forgery(self):
        r, _ = core.soul(b'synthetic')
        for key, value in [('domain', 'other/v1'), ('kind', 'release'), ('network', 'mainnet'), ('representation', 'normalized-v1'), ('commitment', '0' * 64), ('private_nonce', True)]:
            bad = copy.deepcopy(r)
            bad[key] = value
            self.assertFalse(core.verify(bad, b'synthetic'), key)
        for key, value in [('status', 'confirmed'), ('payload_hex', 'f' * 64), ('publication_consent_required', False), ('chain_evidence', 'SPV verified'), ('authorship', 'authentic-human')]:
            bad = copy.deepcopy(r)
            bad['anchor_plan'][key] = value
            self.assertFalse(core.verify(bad, b'synthetic'), key)
        for key in r:
            bad = copy.deepcopy(r)
            del bad[key]
            self.assertFalse(core.verify(bad, b'synthetic'), key)
        self.assertFalse(core.verify(dict(r, verified=True), b'synthetic'))

    def test_recursive_untrusted_receipt_is_rejected(self):
        receipt, _ = core.soul(b'synthetic')
        nested = value = {}
        for _ in range(1500):
            value['nested'] = {}
            value = value['nested']
        receipt['anchor_plan']['payload_hex'] = nested
        self.assertFalse(core.verify(receipt, b'synthetic'))

    def test_no_raw_publication_and_nonce_randomness(self):
        entries = [{'path': 'sensitive-project-name.md', 'data': b'DO-NOT-PUBLISH'}]
        entries[0]['path'] = 'project-name.md'
        a, ap = core.release(entries, private=True)
        b, bp = core.release(entries, private=True)
        self.assertNotEqual(ap['nonce'], bp['nonce'])
        self.assertNotEqual(a['commitment'], b['commitment'])
        for x in ('DO-NOT-PUBLISH', 'project-name.md', ap['nonce']):
            self.assertNotIn(x, json.dumps(a))
        self.assertFalse(core.verify_manifest(a, entries, bp['nonce']))
        self.assertTrue(core.verify_manifest(a, entries, ap['nonce']))

    def test_release_comparison_add_remove(self):
        a = [{'path': 'a.py', 'data': b'a'}]
        b = [{'path': 'b.py', 'data': b'b'}]
        self.assertEqual(core.changes(a, b), {'added': ['b.py'], 'removed': ['a.py'], 'changed': []})
if __name__ == '__main__':
    unittest.main()
