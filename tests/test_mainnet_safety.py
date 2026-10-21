"""Integration attacks use only newly generated unfunded keys and loopback HTTP."""
import copy
import json
import unittest
from unittest.mock import patch
import test_mainnet_workflow as fixture


@unittest.skipUnless(fixture.sdk_ready(), 'requires isolated pinned mainnet extra')
class MainnetSafety(unittest.TestCase):
    setUp = fixture.MainnetWorkflow.setUp
    approve_sign = fixture.MainnetWorkflow.approve_sign

    def ready(self):
        self.runtime.prepare('first', 'attack fixture')
        self.approve_sign()
        return self.runtime.sign('first')

    def test_fake_signing_signature_never_enters_wallet_custody(self):
        from bsv_hermes.mainnet.signer import core
        self.runtime.prepare('first', 'attack fixture'); self.approve_sign()
        with self.runtime.journal.session() as session:
            session.data['workflows']['first']['sign_approval']['signature_hex'] = '00'*64
            session.save()
        with patch.object(core, '_wallet', side_effect=AssertionError('custody touched')) as custody:
            with self.assertRaises(ValueError):
                self.runtime.sign('first')
            custody.assert_not_called()
        self.assertGreater(self.runtime.policy_status()['total']['reserved_sat'], 0)

    def test_signing_loss_retains_budget_input_locks_and_cannot_cancel(self):
        from bsv_hermes.mainnet.signer import LocalSigner
        from bsv_hermes.mainnet.spend_policy import Authority
        self.runtime.prepare('first', 'attack fixture'); self.approve_sign()
        original = LocalSigner.sign
        calls = []
        def lost(signer, plan, approval):
            original(signer, plan, approval)
            calls.append(True)
            raise RuntimeError('SYNTHETIC-PRIVATE-CANARY')
        with patch.object(LocalSigner, 'sign', lost):
            with self.assertRaises(RuntimeError):
                self.runtime.sign('first')
            replay = self.runtime.sign('first')
        self.assertEqual(calls, [True])
        self.assertEqual(replay['budget_receipt']['state'], 'signing')
        with self.assertRaises(ValueError):
            Authority(self.runtime.gate.db_path).cancel(replay['budget_receipt']['reservation_id'])
        self.runtime.prepare('second', 'another intent'); self.approve_sign('second')
        with self.assertRaises(ValueError):
            self.runtime.sign('second')
        self.assertEqual(self.provider.posts, 0)

    def test_budget_cap_applies_to_outstanding_not_just_settled_transactions(self):
        from bsv_hermes.mainnet.runtime import Runtime
        from mainnet_fixtures import Provider
        self.ready()
        # New invented, independent parent/output to avoid the input-lock check.
        newer = Provider(self.runtime.config['wallet'], value=20000)
        self.addCleanup(newer.close)
        next_runtime = Runtime(self.directory, funding_client=newer.funding(),
                               broadcast_transport=newer.broadcast_transport())
        next_runtime.prepare('second', 'second'); self.approve_sign('second'); next_runtime.sign('second')
        third = Provider(self.runtime.config['wallet'], value=30000)
        self.addCleanup(third.close)
        last = Runtime(self.directory, funding_client=third.funding(), broadcast_transport=third.broadcast_transport())
        last.prepare('third', 'third'); self.approve_sign('third')
        with self.assertRaisesRegex(ValueError, 'cap_exceeded'):
            last.sign('third')
        self.assertEqual(last.policy_status()['total']['committed_sat'], 238)

    def test_stale_provider_input_blocks_before_custody_and_reservation(self):
        self.runtime.prepare('first', 'attack fixture'); self.approve_sign()
        self.provider.stale = True
        with self.assertRaisesRegex(ValueError, 'funding_changed'):
            self.runtime.sign('first')
        self.assertEqual(self.runtime.policy_status()['total']['committed_sat'], 0)

    def test_expired_or_revoked_policy_blocks_signing(self):
        from bsv_hermes.mainnet.spend_policy import Authority
        self.runtime.prepare('first', 'attack fixture'); self.approve_sign()
        digest = self.runtime.review('first')['spend_digest']
        Authority(self.runtime.gate.db_path).revoke(self.runtime.config['session_id'], digest)
        with self.assertRaisesRegex(ValueError, 'approval_revoked'):
            self.runtime.sign('first')
        self.assertEqual(self.runtime.policy_status()['total']['committed_sat'], 0)

    def test_ack_without_raw_readback_is_held_and_never_retried(self):
        signed = self.ready()
        self.operator.approve_submit(self.directory, self.authority, 'first', expected_txid=signed['txid'])
        self.provider.ack_only = True
        result = self.runtime.submit('first')
        self.assertEqual(result['stage'], 'uncertain')
        self.assertEqual(result['budget_receipt']['state'], 'uncertain')
        self.assertEqual(self.provider.posts, 1)
        self.runtime.submit('first'); self.runtime.receipt('first')
        self.assertEqual(self.provider.posts, 1)
        with self.runtime.journal.session() as session:
            raw = session.data['workflows']['first']['signed']['signed_transaction_hex']
        self.provider.submitted[signed['txid']] = raw
        self.assertEqual(self.runtime.receipt('first')['stage'], 'submitted')
        self.assertEqual(self.provider.posts, 1)

    def test_forged_submit_grant_blocks_even_provider_preflight(self):
        signed = self.ready()
        self.operator.approve_submit(self.directory, self.authority, 'first', expected_txid=signed['txid'])
        with self.runtime.journal.session() as session:
            session.data['workflows']['first']['submit_approval']['signature_hex'] = 'ff'*64
            session.save()
        before = self.provider.gets
        with self.assertRaisesRegex(ValueError, 'submit_approval_invalid'):
            self.runtime.submit('first')
        self.assertEqual(self.provider.gets, before)
        self.assertEqual(self.provider.posts, 0)

    def test_signed_output_mutation_never_reaches_transport(self):
        signed = self.ready()
        self.operator.approve_submit(self.directory, self.authority, 'first', expected_txid=signed['txid'])
        with self.runtime.journal.session() as session:
            state = session.data['workflows']['first']
            state['signed']['signed_transaction_hex'] = state['signed']['signed_transaction_hex'][:-8] + '01000000'
            session.save()
        with self.assertRaisesRegex(ValueError, 'signature_invalid'):
            self.runtime.submit('first')
        self.assertEqual(self.provider.posts, 0)

    def test_crash_after_dispatch_claim_does_not_enable_resubmission(self):
        from bsv_hermes.mainnet.broadcast.client import BroadcastClient
        signed = self.ready()
        self.operator.approve_submit(self.directory, self.authority, 'first', expected_txid=signed['txid'])
        with patch.object(BroadcastClient, 'submit', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.runtime.submit('first')
        self.assertEqual(self.runtime.status('first')['budget_receipt']['state'], 'dispatching')
        self.runtime.submit('first')
        self.assertEqual(self.runtime.receipt('first')['stage'], 'uncertain')
        self.assertEqual(self.provider.posts, 0)

    def test_simultaneous_callers_share_one_signing_claim(self):
        from concurrent.futures import ThreadPoolExecutor
        self.runtime.prepare('first', 'attack fixture'); self.approve_sign()
        def attempt(_):
            try:
                return self.runtime.sign('first')
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(attempt, range(3)))
        self.assertTrue(any(r and r['signed'] for r in results))
        self.assertEqual(self.runtime.policy_status()['total']['committed_sat'], 119)
