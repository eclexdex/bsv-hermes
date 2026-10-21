import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from bsv_hermes.kits.integrations import core
from bsv_hermes.kits.integrations.operations import dispatch
OVERLAY = dict(network='testnet', service='fixture', provider='fixture', query_digest='11' * 32, result_digest='22' * 32, observed_at=100, nonce='33' * 16)
HANDOFF = dict(network='testnet', task_id='task', parent='parent', child='child', goal_digest='11' * 32, artifact_digests=['22' * 32], previous_digest='00' * 32, sequence=1, issued_at=100, expires_at=200, now=150, nonce='33' * 16, seen=[])

class SecurityV2(unittest.TestCase):

    def test_private_opening_not_returned_and_roundtrip_works(self):
        for action, args in [('overlay', OVERLAY), ('handoff', HANDOFF)]:
            result = dispatch(action, args)
            self.assertTrue(result['ok'])
            self.assertNotIn(args['nonce'], json.dumps(result))
            receipt = result['data']
            checked = dispatch(action, dict(args, receipt=receipt))
            self.assertTrue(checked['ok'])
            self.assertTrue(checked['data']['integrity_match'])
            wrong = dispatch(action, dict(args, nonce='44' * 16, receipt=receipt))
            self.assertFalse(wrong['data']['integrity_match'])

    def test_envelope_helper_rejects_forged_authentication(self):
        private = dict(domain='fixture', nonce='33' * 16)
        original = core.envelope_receipt(private)
        self.assertTrue(core.envelope_receipt(private, original)['integrity_match'])
        forged = dict(original, authentication='authenticated')
        self.assertFalse(core.envelope_receipt(private, forged)['integrity_match'])

    def test_envelope_integer_boolean_substitution_rejected(self):
        receipt = dispatch('handoff', HANDOFF)['data']
        receipt['envelope']['sequence'] = True
        result = dispatch('handoff', dict(HANDOFF, receipt=receipt))
        self.assertTrue(not result['ok'] or not result['data']['integrity_match'])

    def test_receipt_metadata_is_bound(self):
        for action, args, fields in [('overlay', OVERLAY, ['authentication', 'result_truth', 'provider_identity', 'observation_time', 'overlay_consensus']), ('handoff', HANDOFF, ['authentication', 'peer_authentication', 'authorization', 'artifact_bytes', 'replay_store'])]:
            receipt = dispatch(action, args)['data']
            for field in fields:
                forged = copy.deepcopy(receipt)
                forged[field] = 'verified'
                result = dispatch(action, dict(args, receipt=forged))
                self.assertTrue(not result['ok'] or not result['data']['integrity_match'], field)
            forged = dict(receipt, fabricated='verified')
            self.assertFalse(dispatch(action, dict(args, receipt=forged))['ok'])

    def test_preflight_rejects_before_serializer(self):
        payloads = ['\x7f' * 11000, '\x00' * 2097152, '\x00' * 11000, 'a' * 65537, {'a' * 65537: 0}, ['\x00' * 2000] * 6, [[None] * 1024] * 8, [[[[[[[[[[[[[0]]]]]]]]]]]]]]
        for value in payloads:
            with self.subTest(kind=type(value).__name__), patch.object(core.json, 'dumps', side_effect=AssertionError('serializer reached')):
                with self.assertRaises(ValueError):
                    core.canonical(value)

    def test_exact_ascii_budget(self):
        for value in [None, True, 12, {'z': '😀', 'a': '\n"\\'}, ['é', '\x00']]:
            expected = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
            self.assertEqual(core.canonical(value), expected)
        self.assertEqual(len(core.canonical('a' * (core.MAX_BYTES - 2))), core.MAX_BYTES)
if __name__ == '__main__':
    unittest.main()
