import copy
import hashlib
import json
from pathlib import Path
import unittest
from bsv_hermes.kits.assurance import core
from bsv_hermes.kits.assurance.operations import handler

def bundle(**overrides):
    a = core.artifact({'network': 'testnet', 'items': [{'digest': 'a' * 64, 'bytes': 3}], 'nonce': 'b' * 64})
    c = core.chain({'network': 'testnet', 'events': [{'call_digest': 'a' * 64, 'phase': 'attempt', 'outcome': 'pending'}, {'call_digest': 'a' * 64, 'phase': 'terminal', 'outcome': 'ok'}], 'nonce': 'c' * 64})
    v = dict(network='testnet', artifact=a, chain=c, required_digests=['a' * 64], max_age=30, observed_at=100, now=110)
    v.update(overrides)
    return v

class GateRegression(unittest.TestCase):

    def test_all_27_audited_schema_invalid_inputs_are_errors(self):
        cases = json.loads(Path(__file__).with_name('gate_invalid_cases.json').read_text())
        self.assertEqual(len(cases), 27)
        for case in cases:
            with self.subTest(case=case['case']):
                result = handler('deployment_gate')(case['input'])
                self.assertEqual(result, {'ok': False, 'error': {'code': 'invalid_evidence'}})

    def test_valid_insufficient_evidence_is_not_input_error(self):
        for v in (bundle(required_digests=['d' * 64]), bundle(now=131)):
            result = handler('deployment_gate')({'evidence': v})
            self.assertTrue(result['ok'])
            self.assertFalse(result['data']['evidence_ready'])
            self.assertEqual(result['data']['mode'], 'advisory_only')
            self.assertEqual(result['data']['deployment_safety'], 'not_certified')

    def test_network_only_mismatch(self):
        r = core.gate(bundle(network='mainnet'))
        for key in ('integrity', 'complete', 'fresh_supplied_timestamp'):
            self.assertTrue(r[key])
        self.assertFalse(r['network_matches'])
        self.assertFalse(r['evidence_ready'])

    def test_time_boundaries_only(self):
        self.assertTrue(core.gate(bundle(now=130))['evidence_ready'])
        for now in (99, 131):
            r = core.gate(bundle(now=now))
            for key in ('integrity', 'network_matches', 'complete'):
                self.assertTrue(r[key])
            self.assertFalse(r['fresh_supplied_timestamp'])
            self.assertFalse(r['evidence_ready'])

    def test_bool_is_never_integer(self):
        for value in (True, False):
            with self.assertRaises(core.Invalid):
                core.integer(value)

    def test_independent_second_link_record(self):
        c = bundle()['chain']
        record = {'previous': c['links'][0], 'event': c['projection']['events'][1], 'index': 1, 'network': 'testnet', 'nonce': 'c' * 64}
        raw = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        expected = hashlib.sha256(b'hermes-assurance/v1\x00tool-chain-link\x00' + raw).hexdigest()
        self.assertEqual(c['links'][1], expected)
