import unittest
from bsv_hermes.kits.assurance import core

class ArtifactTests(unittest.TestCase):

    def test_receipt_private_and_domain_bound(self):
        r = core.artifact({'network': 'testnet', 'items': [{'digest': 'a' * 64, 'bytes': 3}], 'nonce': 'b' * 64})
        self.assertEqual(r['kind'], 'artifact')
        self.assertNotEqual(r['digest'], core.commit('other', r['projection']))
        self.assertNotIn('contents', str(r))

class ChainTests(unittest.TestCase):

    def test_attempt_outcomes_and_tamper(self):
        events = [{'call_digest': 'a' * 64, 'phase': 'attempt', 'outcome': 'pending'}, {'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': 'cancelled'}]
        c = core.chain({'network': 'testnet', 'events': events, 'nonce': 'b' * 64})
        self.assertTrue(core.verify_chain(c))
        c['projection']['events'][1]['outcome'] = 'ok'
        self.assertFalse(core.verify_chain(c))

    def test_bad_order(self):
        with self.assertRaises(core.Invalid):
            core.chain({'network': 'testnet', 'events': [{'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': 'denied'}], 'nonce': 'b' * 64})

class ApprovalTests(unittest.TestCase):

    def test_binding_expiry_replay(self):
        intent = {'network': 'testnet', 'action_digest': 'a' * 64, 'nonce': 'b' * 64, 'issued_at': 100, 'expires_at': 200}
        token = {'intent_digest': core.commit('approval-intent', intent), 'nonce': 'b' * 64}
        self.assertTrue(core.approval({'intent': intent, 'token': token, 'now': 150, 'used_nonces': []})['evidence_matches'])
        for now, used in [(200, []), (150, ['b' * 64]), (99, [])]:
            self.assertFalse(core.approval({'intent': intent, 'token': token, 'now': now, 'used_nonces': used})['evidence_matches'])
        intent['network'] = 'mainnet'
        self.assertFalse(core.approval({'intent': intent, 'token': token, 'now': 150, 'used_nonces': []})['evidence_matches'])

class GateTests(unittest.TestCase):

    def test_bundle_digest_and_missing_evidence(self):
        a = core.artifact({'network': 'testnet', 'items': [{'digest': 'a' * 64, 'bytes': 3}], 'nonce': 'b' * 64})
        c = core.chain({'network': 'testnet', 'events': [{'call_digest': 'a' * 64, 'phase': 'attempt', 'outcome': 'pending'}, {'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': 'ok'}], 'nonce': 'c' * 64})
        v = {'network': 'testnet', 'artifact': a, 'chain': c, 'required_digests': ['a' * 64], 'max_age': 30, 'observed_at': 100, 'now': 110}
        self.assertTrue(core.gate(v)['evidence_ready'])
        v['required_digests'] = ['d' * 64]
        self.assertFalse(core.gate(v)['evidence_ready'])
        v['network'] = 'mainnet'
        self.assertFalse(core.gate(v)['evidence_ready'])

class PrivacyTests(unittest.TestCase):

    def test_projection_limits_and_missing(self):
        good = {'network': 'testnet', 'items': [{'digest': 'a' * 64, 'bytes': 3}], 'nonce': 'b' * 64}
        for v in [{}, dict(good, contents='secret'), dict(good, nonce='x'), dict(good, network='other'), dict(good, items=good['items'] * 129), dict(good, nonce='x' * 70000)]:
            with self.assertRaises(core.Invalid):
                core.artifact(v)

class HardeningTests(unittest.TestCase):

    def test_all_terminal_outcomes_and_pending(self):
        for outcome in ('ok', 'error', 'denied', 'cancelled', 'unknown'):
            v = {'network': 'testnet', 'events': [{'call_digest': 'a' * 64, 'phase': 'attempt', 'outcome': 'pending'}, {'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': outcome}], 'nonce': 'b' * 64}
            self.assertTrue(core.verify_chain(core.chain(v)))
        v['events'].pop()
        self.assertEqual(core.chain(v)['pending_count'], 1)

    def test_reorder_duplicate_and_truncate(self):
        v = {'network': 'testnet', 'events': [{'call_digest': 'a' * 64, 'phase': 'attempt', 'outcome': 'pending'}, {'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': 'ok'}], 'nonce': 'b' * 64}
        c = core.chain(v)
        c['links'].reverse()
        self.assertFalse(core.verify_chain(c))
        v['events'] *= 2
        with self.assertRaises(core.Invalid):
            core.chain(v)
if __name__ == '__main__':
    unittest.main()
