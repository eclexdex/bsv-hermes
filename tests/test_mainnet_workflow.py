import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
import unittest


def sdk_ready():
    try:
        return (importlib.metadata.version('bsv-sdk') == '2.4.0'
                and importlib.metadata.version('cryptography') == '48.0.0')
    except importlib.metadata.PackageNotFoundError:
        return False


@unittest.skipUnless(sdk_ready(), 'requires isolated pinned mainnet extra; never a host-only pass')
class MainnetWorkflow(unittest.TestCase):
    def setUp(self):
        from bsv_hermes.mainnet import operator, runtime
        from mainnet_fixtures import Provider
        self.temp = tempfile.TemporaryDirectory(prefix='bsv-mainnet-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.directory = str(self.path/'runtime')
        self.authority = str(self.path/'operator-only')
        self.operator = operator
        public = operator.initialize(self.directory, self.authority, total_cap_sat=300,
                                     max_fee_sat=150, fee_rate_sat_kb=500)
        self.provider = Provider(public)
        self.addCleanup(self.provider.close)
        self.runtime_class = runtime.Runtime
        self.runtime = runtime.Runtime(self.directory, funding_client=self.provider.funding(),
                                       broadcast_transport=self.provider.broadcast_transport())

    def test_prepare_binds_funding_builder_and_signer_without_spending(self):
        from bsv_hermes.mainnet.signer import plan_digest
        quoted = self.runtime.prepare('first', 'synthetic never funded')
        self.assertEqual(quoted['stage'], 'built')
        self.assertEqual(quoted['network'], 'mainnet')
        self.assertFalse(quoted['signed'])
        review = self.runtime.review('first')
        self.assertEqual(plan_digest(review['signing_plan']), quoted['signing_digest'])
        self.assertEqual(review['signing_plan']['inputs'][0]['source_transaction_hex'], self.provider.raw)
        self.assertEqual(review['signing_plan']['outputs'][0]['locking_script_hex'],
                         '006a20' + quoted['digest_hex'])
        self.assertEqual(quoted['cost_sat'], quoted['fee_sat'])
        self.assertEqual(self.runtime.policy_status()['total']['committed_sat'], 0)
        self.assertEqual(self.provider.posts, 0)
        self.assertNotIn('synthetic never funded', (self.path/'runtime/publish/state.json').read_text())
        self.assertEqual(self.runtime.prepare('first', 'synthetic never funded'), quoted)
        with self.assertRaises(ValueError):
            self.runtime.prepare('first', 'changed')

    def approve_sign(self, workflow_id='first'):
        review = self.runtime.review(workflow_id)
        return self.operator.approve_sign(self.directory, self.authority, workflow_id,
            expected_digest=review['signing_digest'], max_cost_sat=150)

    def test_operator_approval_then_durable_lock_before_real_sdk_signing(self):
        from unittest.mock import patch
        from bsv_hermes.mainnet.signer import LocalSigner, verify_signed_transaction
        self.runtime.prepare('first', 'signing test')
        with self.assertRaises(ValueError):
            self.runtime.sign('first')
        self.assertEqual(self.runtime.policy_status()['total']['committed_sat'], 0)
        self.approve_sign()
        original = LocalSigner.sign
        calls = []
        runtime = self.runtime
        def checked(signer, plan, approval):
            from bsv_hermes.mainnet.signer.storage import read_private_json
            state = read_private_json(str(runtime.root/'publish/state.json'), 1048576)['workflows']['first']
            receipt = runtime.gate.receipt(state['reservation_id'])
            self.assertEqual(receipt['state'], 'signing')
            self.assertEqual(runtime.policy_status()['total']['reserved_sat'], receipt['cost_sat'])
            calls.append(True)
            return original(signer, plan, approval)
        with patch.object(LocalSigner, 'sign', checked):
            signed = self.runtime.sign('first')
        self.assertTrue(signed['signed'])
        self.assertEqual(signed['budget_receipt']['state'], 'prepared')
        self.assertEqual(calls, [True])
        with self.runtime.journal.session() as session:
            state = session.data['workflows']['first']
            self.assertTrue(verify_signed_transaction(state['signing_plan'],
                state['signed']['signed_transaction_hex'], self.runtime.config['wallet']['public_key_hex']))
        self.assertNotIn('signed_transaction_hex', json.dumps(signed))
        self.assertEqual(self.runtime.sign('first'), signed)
        self.assertEqual(self.provider.posts, 0)

    def test_native_broker_uses_real_isolated_worker_without_secrets(self):
        import sys
        from bsv_hermes import adapter
        specs = adapter.tool_specs(['mainnet'], mainnet_directory=self.directory, mainnet_python=sys.executable)
        address = json.loads(specs['bsv_wallet_address'][0]({}))
        self.assertTrue(address['ok'], address)
        self.assertEqual(address['result'], self.runtime.address())
        status = json.loads(specs['bsv_spend_policy_status'][0]({}))
        self.assertEqual(status['result']['total']['committed_sat'], 0)
        missing = json.loads(specs['bsv_publish_status'][0]({'workflow_id': 'missing'}))
        self.assertFalse(missing['ok'])
        self.assertNotIn(self.directory, json.dumps(missing))
        self.assertNotIn('private_key', json.dumps(address))

    def test_separate_submit_approval_real_http_and_exact_readback(self):
        self.runtime.prepare('first', 'publish test')
        self.approve_sign()
        signed = self.runtime.sign('first')
        with self.assertRaises(ValueError):
            self.runtime.submit('first')
        self.assertEqual(self.provider.posts, 0)
        self.operator.approve_submit(self.directory, self.authority, 'first', expected_txid=signed['txid'])
        result = self.runtime.submit('first')
        self.assertEqual(result['stage'], 'submitted')
        self.assertTrue(result['observation']['readback']['raw_txid_verified'])
        self.assertEqual(result['txid'], signed['txid'])
        self.assertEqual(result['budget_receipt']['state'], 'settled')
        self.assertEqual(self.provider.posts, 1)
        self.assertEqual(self.runtime.submit('first')['txid'], signed['txid'])
        reopened = self.runtime_class(self.directory, funding_client=self.provider.funding(),
                                       broadcast_transport=self.provider.broadcast_transport())
        self.assertEqual(reopened.receipt('first')['txid'], signed['txid'])
        self.assertEqual(self.provider.posts, 1)
