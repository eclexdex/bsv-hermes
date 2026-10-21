"""Integrated receipt tracers, not expectations derived from producer output."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

FIXTURES = Path(__file__).parent / 'receipt_vectors'


def request():
    def part(name, raw):
        return {'id': name, 'bytes_b64': base64.b64encode(raw).decode()}
    return {'run_id': 'synthetic-only', 'instruction': part('instruction', b'abc'),
            'approved_inputs': [], 'tools': [], 'final_output': part('output', b'')}


class ReceiptIntegration(unittest.TestCase):
    def test_exact_grants_do_not_erase_symlink_dotdot_components(self):
        from bsv_hermes.receipts import verifier
        from bsv_hermes.receipts.cli import write_new
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'target').write_bytes(b'abc')
            (root/'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                verifier.read_regular(root/'link/../target', 10)
            with self.assertRaises(ValueError):
                write_new(root/'link/../output', b'x')

    def test_producer_size_within_verifier_profile(self):
        from bsv_hermes.receipts.producer import build_run
        req = request()
        req['instruction'] = {'id':'instruction','sha256':'00'*32,'size':16777217}
        with self.assertRaises(ValueError):
            build_run(req)

    def test_versioned_batch_report_and_inert_publisher_binding(self):
        from bsv_hermes.receipts import producer
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts.evidence'), 'versioned evidence adapter missing')
        from bsv_hermes.receipts.evidence import build_batch, verify, ADAPTER
        from bsv_hermes import domain
        bundle = producer.build_run(request())['bundle']
        batch = build_batch([('run-one', bundle)], nonces=['01'*32], export_private_proofs=True, workflow_id='synthetic-batch')
        self.assertEqual(batch, build_batch([('run-one', bundle)], nonces=['01'*32], export_private_proofs=True, workflow_id='synthetic-batch'))
        publication = batch['publication_request']
        self.assertEqual(publication['tool'], 'bsv_publish_prepare')
        plan = domain.plan_commitment(publication['arguments']['text'])
        self.assertEqual(publication['expected_commitment_script_hex'], plan['locking_script_hex'])
        envelope = {'adapter': ADAPTER, 'bundle': bundle, 'batch': batch['private_proofs'][0]}
        report = verify(envelope, batch_commitment=batch['manifest']['commitment'])
        self.assertEqual(set(report['results']), {'artifact', 'chain', 'signature', 'batch', 'inclusion', 'publication'})
        self.assertEqual(report['results']['batch']['status'], 'match')
        self.assertEqual(report['results']['artifact']['status'], 'unchecked')
        self.assertEqual(report['results']['publication']['status'], 'missing')
        self.assertEqual(verify(envelope)['results']['batch']['status'], 'unchecked')
        self.assertEqual(verify(envelope, batch_commitment='00'*32)['results']['batch']['status'], 'mismatch')
        wrong = copy.deepcopy(envelope); wrong['bundle']['instruction']['sha256'] = '00'*32
        self.assertEqual(verify(wrong, batch_commitment=batch['manifest']['commitment'])['results']['batch']['status'], 'mismatch')
        self.assertNotIn('private_proofs', build_batch([('one', bundle)], nonces=['01'*32]))
        with self.assertRaises(ValueError):
            build_batch([('one', wrong['bundle'])], nonces=['01'*32])

    def test_library_budget_before_json_serialization(self):
        from bsv_hermes.receipts import verifier
        from unittest.mock import patch
        with patch.object(verifier.json, 'dumps', side_effect=AssertionError('serialized before bound')):
            with self.assertRaises(verifier.Invalid):
                verifier.verify({'huge': '\x00' * (verifier.MAX_JSON + 1)})

    def test_native_receipt_is_optional_and_validated(self):
        from bsv_hermes.adapter import tool_specs
        self.assertNotIn('bsv_assurance_run', tool_specs())
        specs = tool_specs(['assurance'])
        self.assertIn('bsv_assurance_run', specs)
        handler = specs['bsv_assurance_run'][0]
        reply = json.loads(handler(request()))
        self.assertTrue(reply['ok'])
        self.assertEqual(reply['result']['bundle']['version'], 'hermes-receipt/v1')
        bad = request(); bad['instruction']['size'] = True
        self.assertFalse(json.loads(handler(bad))['ok'])

    def test_producer_independent_verifier_roundtrip(self):
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts'), 'receipt package missing')
        from bsv_hermes.receipts.producer import build_run
        from bsv_hermes.receipts import verifier
        from bsv_hermes.receipts.contract import validate
        value = build_run(request())
        bundle = value['bundle']
        self.assertEqual(bundle['instruction']['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        validate(bundle)
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d)/'instruction', Path(d)/'output'
            a.write_bytes(b'abc'); b.write_bytes(b'')
            report = verifier.verify(bundle, {'instruction': a, 'output': b})
            self.assertEqual([x['status'] for x in report['artifact_bytes']], ['match', 'match'])
            self.assertEqual(report['evidence_chain']['status'], 'match')
            self.assertEqual(report['signature']['status'], 'missing')
            self.assertEqual(report['batch']['status'], 'missing')
            self.assertEqual(report['inclusion']['selected_chain']['status'], 'unchecked')
            b.write_bytes(b'tamper')
            self.assertEqual(verifier.verify(bundle, {'output': b})['artifact_bytes'][-1]['status'], 'mismatch')
        self.assertNotIn('verified', report)
        golden = json.loads((FIXTURES/'contract/golden.json').read_text())
        self.assertEqual(verifier.verify(golden)['evidence_chain']['status'], 'match')
        bad = copy.deepcopy(golden); bad['tools'].reverse()
        self.assertEqual(verifier.verify(bad)['evidence_chain']['status'], 'mismatch')
