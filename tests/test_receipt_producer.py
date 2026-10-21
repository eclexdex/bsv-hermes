import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from bsv_hermes.receipts.native import handler
from bsv_hermes.receipts.producer import build_run, canonical, load_request


def a(name, data=b''):
    return {'id': name, 'bytes_b64': base64.b64encode(data).decode('ascii')}


def fixture():
    return {'run_id': 'synthetic-neverfunded', 'instruction': a('instruction', b'Inspect synthetic script'),
            'approved_inputs': [a('input', b'006a')],
            'tools': [{'id': 'event-0', 'name': 'bsv_inspect_script', 'arguments': a('args', b'{"script_hex":"006a"}'),
                       'result': a('tool-result', b'{"synthetic":true}'), 'source': 'explicit_wrapper_recorded'}],
            'final_output': a('output', b'Synthetic inspection complete')}


class RunTests(unittest.TestCase):
    def test_roundtrip_contract_preimages_independent(self):
        value = build_run(fixture()); b = value['bundle']
        def oracle(label, obj):
            text = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
            return hashlib.sha256(b'hermes-receipt/v1/' + label.encode() + b'\x00' + text.encode()).hexdigest()
        start = oracle('start', {'instruction': b['instruction'], 'approved_inputs': b['approved_inputs']})
        self.assertEqual(b['tools'][0]['previous'], start)
        event = dict(b['tools'][0]); event.pop('event_digest')
        self.assertEqual(b['tools'][0]['event_digest'], oracle('tool', event))
        unsigned = dict(b); unsigned.pop('receipt_digest')
        self.assertEqual(b['receipt_digest'], oracle('bundle', unsigned))
        self.assertEqual(value['result']['artifact']['status'], 'match')
        for key in ('signature', 'batch', 'inclusion', 'publication'):
            self.assertEqual(value['result'][key]['status'], 'missing')
        self.assertNotIn('bytes_b64', json.dumps(value))

    def test_literal_empty_sha(self):
        x = fixture(); x['instruction'] = a('instruction')
        self.assertEqual(build_run(x)['bundle']['instruction']['sha256'], 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_digest_only_unchecked(self):
        x = fixture(); x['instruction'] = {'id': 'instruction', 'sha256': '0'*64, 'size': 17}
        self.assertEqual(build_run(x)['result']['artifact']['status'], 'unchecked')
        del x['instruction']['size']
        self.assertFalse(json.loads(handler(x))['ok'])

    def test_size_digest_mismatch(self):
        for extra in ({'size': 9}, {'sha256': '0'*64}, {'sha256': None}, {'sha256': True}, {'size': True}, {'size': 1.0}, {'bytes_b64': '%%%='}, {'bytes_b64': 'Zh=='}):
            x = fixture(); x['instruction'].update(extra)
            self.assertFalse(json.loads(handler(x))['ok'])

    def test_global_duplicate_descriptor(self):
        x = fixture(); x['tools'][0]['result']['id'] = 'input'
        self.assertFalse(json.loads(handler(x))['ok'])

    def test_order_and_truncation(self):
        x = fixture(); other = copy.deepcopy(x['tools'][0]); other['id'] = 'event-1'
        other['arguments']['id'] = 'args-1'; other['result']['id'] = 'response-1'
        x['tools'].append(other)
        initial = build_run(x)['bundle']['receipt_digest']
        x['tools'].reverse()
        self.assertNotEqual(initial, build_run(x)['bundle']['receipt_digest'])
        x['tools'] = []
        self.assertNotEqual(initial, build_run(x)['bundle']['receipt_digest'])

    def test_invalid_native_is_sanitized(self):
        x = fixture()
        for bad in (None, [], True, {'unknown': 'SECRET-CANARY'}, dict(x, unknown='SECRET-CANARY')):
            raw = handler(bad)
            self.assertFalse(json.loads(raw)['ok']); self.assertNotIn('SECRET-CANARY', raw)

    def test_budget_cycles_depth(self):
        x = fixture(); x['cycle'] = x
        self.assertFalse(json.loads(handler(x))['ok'])
        x = fixture(); x['instruction']['bytes_b64'] = '\x00' * 1048577
        self.assertFalse(json.loads(handler(x))['ok'])

    def test_duplicate_json(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as td:
            p = Path(td)/'duplicate.json'; p.write_text('{"run_id":"a","run_id":"b"}')
            with self.assertRaises(ValueError): load_request(p)

    def test_source_not_authentication(self):
        x = fixture(); value = build_run(x)
        x['tools'][0]['source'] = 'caller_asserted'
        self.assertEqual(value['bundle'], build_run(x)['bundle'])
        self.assertEqual(value['result']['source']['status'], 'unverified')
        self.assertNotEqual(value['result']['source'], build_run(x)['result']['source'])


if __name__ == '__main__': unittest.main()
