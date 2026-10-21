import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from bsv_hermes.receipts import evidence, producer, verifier
from test_receipt_integration import request


class SignatureComposition(unittest.TestCase):
    def test_explicit_signature_adapter_and_backend_pin(self):
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts.signature'), 'signature adapter missing')
        from bsv_hermes.receipts import signature
        self.assertEqual(signature.PIN, '48.0.0')
        try:
            signature._crypto()
        except ImportError:
            self.skipTest('optional pinned cryptography 48.0.0 unavailable')
        bundle = producer.build_run(request())['bundle']
        # Synthetic never-used test seed; no wallet or private-key file IO.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'bsv-hermes offline composition fixture').digest())
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        fp = hashlib.sha256(public).hexdigest()
        sidecar = {'version': 1, 'domain': 'bsv-hermes/receipt-signature/v1', 'algorithm': 'Ed25519',
                   'public_key_sha256': fp, 'bundle_sha256': hashlib.sha256(verifier.contract_canonical(bundle)).hexdigest(),
                   'issued_at': 100, 'expires_at': 200, 'nonce': 'ab'*16}
        raw = b'bsv-hermes/receipt-signature/v1\x00' + json.dumps(sidecar, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        sidecar['signature'] = base64.b64encode(key.sign(raw)).decode()
        value = {'adapter': evidence.ADAPTER, 'bundle': bundle, 'signature': sidecar}
        def verify(**kw):
            return evidence.verify(value, **kw)['results']['signature']
        self.assertEqual(verify(trusted_key=public.hex(), now=150)['status'], 'match')
        self.assertEqual(verify()['status'], 'unchecked')
        self.assertEqual(verify(trusted_key=public.hex())['status'], 'unchecked')
        self.assertEqual(verify(trusted_key='00'*32, now=150)['status'], 'mismatch')
        self.assertEqual(verify(trusted_key=public.hex(), now=200)['status'], 'mismatch')
        with patch.object(signature, '_crypto', side_effect=ImportError):
            self.assertEqual(verify(trusted_key=public.hex(), now=150)['status'], 'unchecked')
        value['bundle']['receipt_digest'] = '00'*32
        self.assertEqual(verify(trusted_key=public.hex(), now=150)['status'], 'mismatch')


class InclusionComposition(unittest.TestCase):
    def test_batch_to_exact_output_and_header_not_selected_chain(self):
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts.inclusion'), 'inclusion adapter missing')
        bundle = producer.build_run(request())['bundle']
        batch = evidence.build_batch([('one', bundle)], nonces=['01'*32], export_private_proofs=True, workflow_id='fixture')
        script = bytes.fromhex(batch['publication_request']['expected_commitment_script_hex'])
        # Independent synthetic legacy tx and header, never a public transaction.
        raw = bytes.fromhex('0100000001'+'00'*32+'0000000000ffffffff010000000000000000') + bytes([len(script)]) + script + bytes(4)
        txhash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
        header = bytes(36) + txhash + bytes(4) + bytes.fromhex('ffff7f20') + bytes(4)
        # supplied-target PoW need not pass for an intentionally unmined header.
        sidecar = {'version': 'bsv-hermes/publication-evidence/v1', 'raw_tx_hex': raw.hex(),
                   'header_hex': header.hex(), 'merkle_path': {'index': 0, 'siblings': []},
                   'provider_report': {'included': True}}
        value = {'adapter': evidence.ADAPTER, 'bundle': bundle, 'batch': batch['private_proofs'][0], 'inclusion': sidecar}
        report = evidence.verify(value, batch_commitment=batch['manifest']['commitment'], expected_txid=txhash[::-1].hex())['results']
        self.assertEqual(report['inclusion']['checks']['commitment']['status'], 'match')
        self.assertEqual(report['inclusion']['checks']['commitment_binding']['status'], 'match')
        self.assertEqual(report['inclusion']['checks']['merkle_header']['status'], 'match')
        self.assertEqual(report['inclusion']['checks']['selected_chain']['status'], 'unchecked')
        self.assertNotEqual(report['inclusion']['status'], 'match')
        self.assertEqual(report['publication']['status'], 'unchecked')
        lie = {'adapter': evidence.ADAPTER, 'bundle': bundle, 'inclusion': {'version': 'bsv-hermes/publication-evidence/v1', 'provider_report': {'included': True}}}
        result = evidence.verify(lie)['results']
        self.assertEqual(result['inclusion']['status'], 'missing')
        self.assertEqual(result['publication']['status'], 'unchecked')
        bad = copy.deepcopy(value); bad['inclusion']['raw_tx_hex'] = raw.hex()[:-2]+'ff'
        report = evidence.verify(bad, batch_commitment=batch['manifest']['commitment'], expected_txid=txhash[::-1].hex())
        self.assertEqual(report['results']['inclusion']['checks']['txid']['status'], 'mismatch')
        with self.assertRaises(ValueError):
            evidence.verify(dict(value, adapter='hermes-receipt/v1-external-v1'))
