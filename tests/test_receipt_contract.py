import copy
import hashlib
import json
from pathlib import Path
import unittest
from bsv_hermes.receipts import contract as r

ROOT = Path(__file__).resolve().parent / 'receipt_vectors'

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.b = r.loads((ROOT / 'contract/golden.json').read_text())
        self.a = {k: bytes.fromhex(v) for k, v in json.loads((ROOT / 'contract/artifacts.json').read_text()).items()}

    def test_literal_vectors_and_builder(self):
        b = self.b
        rebuilt = r.build(b['instruction'], b['approved_inputs'], [(e['tool'], e['request'], e['response']) for e in b['tools']], b['final_output'])
        self.assertEqual(rebuilt, b)
        p = json.loads((ROOT / 'contract/preimages.json').read_text())
        self.assertEqual(r.preimage('start', {k: b[k] for k in ('instruction', 'approved_inputs')}).hex(), p['start'])
        self.assertEqual(hashlib.sha256(bytes.fromhex(p['start'])).hexdigest(), b['tools'][0]['previous'])
        for i, e in enumerate(b['tools']):
            self.assertEqual(r.preimage('tool', {k: v for k, v in e.items() if k != 'event_digest'}).hex(), p['tool-' + str(i)])
            self.assertEqual(hashlib.sha256(bytes.fromhex(p['tool-' + str(i)])).hexdigest(), e['event_digest'])
        self.assertEqual(r.preimage('bundle', {k: v for k, v in b.items() if k != 'receipt_digest'}).hex(), p['bundle'])
        self.assertEqual(hashlib.sha256(bytes.fromhex(p['bundle'])).hexdigest(), b['receipt_digest'])

    def test_result_separation(self):
        result = r.validate(self.b, self.a)
        self.assertEqual(result['artifact'], 'verified')
        for key in ('signature', 'batch', 'inclusion'):
            self.assertEqual(result[key], 'unverified_source')
        self.assertFalse(result['authenticated_execution'])
        self.assertEqual(r.validate(self.b)['artifact'], 'unverified_source')
        self.assertEqual(r.validate(self.b, {'instruction': self.a['instruction']})['artifacts_checked'], 1)

    def test_empty_tools(self):
        r.validate(r.loads((ROOT / 'contract/empty-tools.json').read_text()))

    def test_all_descriptor_tampering(self):
        for i in range(7):
            for field, value in [('sha256', '0' * 64), ('size', 999), ('name', 'changed')]:
                b = copy.deepcopy(self.b)
                list(r.descriptors(b))[i][field] = value
                with self.subTest(i=i, field=field), self.assertRaises(ValueError):
                    r.validate(b)

    def test_event_tampering(self):
        for field, value in [('index', 1), ('index', False), ('tool', 'changed'), ('previous', '0' * 64), ('event_digest', '0' * 64)]:
            b = copy.deepcopy(self.b)
            b['tools'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                r.validate(b)
        for events in [list(reversed(self.b['tools'])), self.b['tools'][:1], self.b['tools'] * 2]:
            b = copy.deepcopy(self.b)
            b['tools'] = events
            with self.assertRaises(ValueError):
                r.validate(b)

    def test_strict_shapes(self):
        for change in [lambda b: b.update(extra=True), lambda b: b.pop('version'), lambda b: b.update(version='v2'), lambda b: b['instruction'].update(extra=1), lambda b: b['tools'][0].update(extra=1), lambda b: b['instruction'].update(size=True), lambda b: b['instruction'].update(sha256='A'*64), lambda b: b['final_output'].update(name='instruction'), lambda b: b.update(approved_inputs={})]:
            b = copy.deepcopy(self.b)
            change(b)
            with self.assertRaises(ValueError):
                r.validate(b)

    def test_artifacts(self):
        for a in [{**self.a, 'output': b'tampered'}, {**self.a, 'unknown': b''}, {**self.a, 'output': 'not bytes'}]:
            with self.assertRaises(ValueError):
                r.validate(self.b, a)

    def test_canonical_limits(self):
        for x in [1.0, float('nan'), 9007199254740992, '\ud800', {'\u2603': 1}, (1,), {1: 2}]:
            with self.assertRaises(ValueError):
                r.canonical(x)
        self.assertEqual(r.canonical({'z': '\u2603', 'a': '\n'}), b'{"a":"\\n","z":"\\u2603"}')
        self.assertNotEqual(r.canonical('\u00e9'), r.canonical('e\u0301'))
        with self.assertRaises(ValueError):
            r.preimage('unknown', {})

    def test_json_ambiguity(self):
        for text in ['{"x":1,"x":2}', '{"x":{"y":1,"y":2}}', 'NaN', 'Infinity', '-Infinity']:
            with self.assertRaises(ValueError):
                r.loads(text)

    def test_rehash_is_not_authentication(self):
        b = self.b
        b['final_output'] = r.descriptor('output', b'attacker supplied')
        b['receipt_digest'] = r.digest('bundle', {k: v for k, v in b.items() if k != 'receipt_digest'})
        result = r.validate(b)
        self.assertFalse(result['authenticated_execution'])
        self.assertEqual(result['signature'], 'unverified_source')
        with self.assertRaises(ValueError):
            r.validate(b, self.a)

if __name__ == '__main__':
    unittest.main()
