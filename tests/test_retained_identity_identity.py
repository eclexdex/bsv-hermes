import unittest
import importlib.util
from pathlib import Path
import tempfile

class IdentityTests(unittest.TestCase):

    def test_soul_exact_private_domain(self):
        from bsv_hermes.kits.identity.core import soul, verify
        a, private = soul(b'PRIVATE synthetic\r\n', 'testnet', private=True)
        self.assertNotIn('PRIVATE', str(a))
        self.assertNotIn(private['nonce'], str(a))
        self.assertTrue(verify(a, b'PRIVATE synthetic\r\n', private['nonce']))
        self.assertFalse(verify(a, b'PRIVATE synthetic\n', private['nonce']))
        b, _ = soul(b'PRIVATE synthetic\r\n', 'mainnet')
        self.assertNotEqual(a['commitment'], b['commitment'])
        self.assertEqual(a['representation'], 'exact-bytes-v1')

class PostureTests(unittest.TestCase):

    def test_projection_has_no_secrets_and_rejects_unknown(self):
        from bsv_hermes.kits.identity.core import posture, posture_preimage, verify
        fields = {'hermes_version': '0.9.0', 'approval_mode': 'required', 'network_access': 'disabled', 'max_iterations': 10, 'telemetry_enabled': False}
        receipt, _ = posture(fields)
        self.assertTrue(verify(receipt, posture_preimage(fields)))
        self.assertNotIn('approval_mode', str(receipt))
        for bad in [dict(fields, api_key='SECRET'), dict(fields, approval_mode='SECRET'), {}, dict(fields, max_iterations=True)]:
            with self.assertRaises(ValueError):
                posture(bad)

class ReleaseTests(unittest.TestCase):

    def test_release_changes_and_separate_purpose(self):
        from bsv_hermes.kits.identity.core import release, changes, verify_manifest, manifest
        before = [{'path': 'plugin.yaml', 'data': b'name: synthetic'}, {'path': 'deps.lock', 'data': b'example==1'}]
        after = [{'path': 'plugin.yaml', 'data': b'name: synthetic'}, {'path': 'deps.lock', 'data': b'example==2'}]
        r, _ = release(before)
        self.assertTrue(verify_manifest(r, before))
        self.assertFalse(verify_manifest(r, after))
        self.assertEqual(changes(before, after), {'added': [], 'removed': [], 'changed': ['deps.lock']})
        instructions, _ = manifest(before)
        self.assertNotEqual(r['commitment'], instructions['commitment'])
        for field in ['domain', 'network', 'kind', 'representation', 'commitment']:
            tampered = dict(r, **{field: 'wrong'})
            self.assertFalse(verify_manifest(tampered, before))
if __name__ == '__main__':
    unittest.main()
