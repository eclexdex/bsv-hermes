"""One digest-publication workflow; no caller-provided authority or custody paths.

Trusted startup constructs this coordinator. Operator administration is separate.
All uncertain signing/submission outcomes retain both budget and input locks.
"""
import json
from pathlib import Path

from . import builder, spend_policy as policy
from .funding import PublicTarget, FundingClient
from .publish.workflow import plan as commitment_plan
from .publish.journal import Journal
from .signer import plan_digest
from .signer.storage import read_private_json, path_parts


class MainnetError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise MainnetError(code)


def bundle(config, snapshot, digest):
    public = config['wallet']
    target = PublicTarget.from_wallet_metadata(public)
    require(snapshot['network'] == 'mainnet' and snapshot['address'] == target.address
            and snapshot['observation_complete'] is True, 'funding_binding')
    inputs = snapshot['utxos']
    require(0 < len(inputs) <= 20, 'funding_required')
    request = {'schema': 'bsv-unsigned-build-request-v1', 'network': 'mainnet',
               'operation': 'publication', 'utxos': [dict(
                   {k: p[k] for k in ('txid', 'vout', 'satoshis', 'locking_script_hex')},
                   unlocking_template='p2pkh-compressed') for p in inputs],
               'outputs': [], 'change': {'address': public['address']},
               'data_hex_chunks': [digest], 'fee_policy': {
                   'satoshis_per_kilobyte': config['fee_rate_sat_kb'],
                   'dust_threshold_satoshis': 1, 'dust_change': 'reject',
                   'max_fee_satoshis': config['max_fee_sat'], 'max_transaction_bytes': 100000}}
    built = builder.build_unsigned(request)
    signing = {'schema': 'bsv-signing-plan-v1', 'network': 'mainnet',
               'wallet_id': public['wallet_id'], 'operation': 'publish', 'version': 1,
               'lock_time': 0, 'sighash': 65,
               'inputs': [dict({k: p[k] for k in ('txid', 'vout', 'satoshis', 'locking_script_hex',
                                                'source_transaction_hex')}, sequence=4294967295) for p in inputs],
               'outputs': [dict({k: p[k] for k in ('role', 'satoshis', 'locking_script_hex')},
                                address=public['address'] if p['role'] == 'change' else None)
                           for p in built['outputs']],
               'payment_satoshis': 0, 'fee_satoshis': built['fee_satoshis'],
               'unsigned_transaction_hex': built['unsigned_transaction_hex']}
    signing_digest = plan_digest(signing)  # independently parses and binds every parent
    spending = {'version': 1, 'network': 'mainnet', 'action': 'publish', 'tx_version': 1,
                'locktime': 0, 'max_signed_bytes': built['maximum_signed_size_bytes'],
                'inputs': [dict({k: p[k] for k in ('txid', 'vout', 'satoshis', 'sequence')},
                                locking_script=p['locking_script_hex']) for p in signing['inputs']],
                'outputs': [{'satoshis': p['satoshis'], 'locking_script': p['locking_script_hex'],
                             'kind': p['role']} for p in signing['outputs']], 'fee_sat': built['fee_satoshis']}
    return {'signing_plan': signing, 'spend_plan': spending, 'signing_digest': signing_digest,
            'spend_digest': policy.plan_digest(config['session_id'], spending)}


class Runtime:
    def __init__(self, directory, *, funding_client=None, broadcast_transport=None):
        path_parts(directory)
        self.root = Path(directory)
        self.config = read_private_json(str(self.root/'config.json'), 8192)
        require(set(self.config) == {'schema', 'wallet', 'approval_public_key_hex', 'session_id',
                                    'max_fee_sat', 'fee_rate_sat_kb'}, 'invalid_configuration')
        require(self.config['schema'] == 'bsv-mainnet-runtime-v1', 'invalid_configuration')
        self.target = PublicTarget.from_wallet_metadata(self.config['wallet'])
        require(self.target.network == 'mainnet', 'network_mismatch')
        self.gate = policy.SpendGate(self.root/'budget.sqlite', self.config['session_id'])
        self.journal = Journal(self.root/'publish')
        self.funding_client = funding_client if funding_client is not None else FundingClient()
        self.broadcast_transport = broadcast_transport

    def address(self):
        from .wallet import WalletStore
        public = WalletStore(str(self.root/'wallet')).address(expected_network='mainnet')
        require(public == self.config['wallet'], 'wallet_mismatch')
        return public

    def policy_status(self):
        return self.gate.status()

    def _snapshot(self):
        return self.funding_client.discover(self.target, min_confirmations=1)

    def funding_status(self):
        snapshot = self._snapshot()
        return {k: snapshot[k] for k in ('network', 'address', 'eligible_satoshis',
                 'observation_complete', 'consensus_verified', 'min_confirmations')} | {
                 'utxo_count': len(snapshot['utxos']), 'provenance': snapshot['provenance']}

    def _state(self, session, workflow_id):
        policy.identifier(workflow_id)
        state = session.data['workflows'].get(workflow_id)
        require(type(state) is dict, 'workflow_not_found')
        require(state['signing_digest'] == plan_digest(state['signing_plan'])
                and state['spend_digest'] == policy.plan_digest(self.config['session_id'], state['spend_plan']),
                'stored_intent_mismatch')
        # Re-map from the frozen signing inputs to prevent divergence between the two plans.
        snapshot = {'network': 'mainnet', 'address': self.target.address, 'observation_complete': True,
                    'utxos': state['signing_plan']['inputs']}
        rebuilt = bundle(self.config, snapshot, state['digest_hex'])
        require(all(state[k] == v for k, v in rebuilt.items()), 'stored_intent_mismatch')
        return state

    def _summary(self, state):
        result = {k: state[k] for k in ('workflow_id', 'digest_hex', 'signing_digest', 'spend_digest', 'stage')}
        result.update(network='mainnet', fee_sat=state['spend_plan']['fee_sat'],
                      cost_sat=state['spend_plan']['fee_sat'], signed='signed' in state,
                      broadcast=False if 'reservation_id' not in state else None,
                      consensus_verified=False)
        if 'reservation_id' in state:
            result['budget_receipt'] = self.gate.receipt(state['reservation_id'])
        if 'signed' in state:
            result['txid'] = state['signed']['txid']
        if 'observation' in state:
            result['observation'] = state['observation']
            result['broadcast'] = state['stage'] == 'submitted'
        return result

    def prepare(self, workflow_id, text):
        policy.identifier(workflow_id)
        digest = commitment_plan(text)['digest_hex']
        with self.journal.session() as session:
            if workflow_id in session.data['workflows']:
                state = self._state(session, workflow_id)
                require(state['digest_hex'] == digest, 'workflow_conflict')
                return self._summary(state)
            require(len(session.data['workflows']) < 256, 'journal_full')
            state = dict(bundle(self.config, self._snapshot(), digest), workflow_id=workflow_id,
                         digest_hex=digest, stage='built')
            self.gate.check(state['spend_plan'])
            session.data['workflows'][workflow_id] = state
            session.save()
            return self._summary(state)

    def _fresh_inputs(self, state):
        snapshot = self._snapshot()
        live = {(p['txid'], p['vout']): p for p in snapshot['utxos']}
        for inp in state['signing_plan']['inputs']:
            row = live.get((inp['txid'], inp['vout']))
            require(row is not None and all(row[k] == inp[k] for k in
                    ('satoshis', 'locking_script_hex', 'source_transaction_hex')), 'funding_changed')

    def sign(self, workflow_id):
        from .signer import LocalSigner, SignerConfig
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            if 'reservation_id' in state:
                return self._summary(state)  # at most once, even a lost signer result
            require('sign_approval' in state, 'operator_approval_required')
            self._fresh_inputs(state)
            reservation = self.gate.reserve(state['spend_plan'])
            state.update(reservation_id=reservation['reservation_id'], stage='signing')
            session.save()  # record identity before the no-refund custody claim
            if not reservation['created']:
                return self._summary(state)
            self.gate.begin_signing(state['reservation_id'])
            cfg = self.config
            signer = LocalSigner(SignerConfig(
                key_file=str(self.root/'wallet/wallet.json'), state_directory=str(self.root/'signer-state'),
                network='mainnet', wallet_id=cfg['wallet']['wallet_id'],
                approval_public_key_hex=cfg['approval_public_key_hex'],
                max_fee_satoshis=cfg['max_fee_sat'], max_payment_satoshis=0))
            signed = signer.sign(state['signing_plan'], state['sign_approval'])
            # prepare independently binds every wire/economic field and checks live approval.
            self.gate.prepare(state['reservation_id'], signed['signed_transaction_hex'])
            state.update(signed=signed, stage='signed')
            session.save()
            return self._summary(state)

    def _submit_authorized(self, state, scope=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from .signer.core import canonical
        import time
        token = state.get('submit_approval')
        require(type(token) is dict and set(token) == {'schema', 'network', 'provider', 'wallet_id',
                'signing_digest', 'txid', 'approval_id', 'issued_at', 'expires_at', 'signature_hex'},
                'submit_approval_required')
        require(token['schema'] == 'bsv-submit-approval-v1' and token['network'] == 'mainnet'
                and token['provider'] == 'whatsonchain' and token['wallet_id'] == self.config['wallet']['wallet_id']
                and token['signing_digest'] == state['signing_digest'] and token['txid'] == state['signed']['txid'],
                'submit_approval_mismatch')
        require(type(token['issued_at']) is int and type(token['expires_at']) is int and
                token['issued_at'] <= int(time.time()) < token['expires_at'] <= token['issued_at']+300,
                'submit_approval_expired')
        try:
            body = {k: v for k, v in token.items() if k != 'signature_hex'}
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.config['approval_public_key_hex'])).verify(
                bytes.fromhex(token['signature_hex']), b'bsv-submit-approval-v1\0' + canonical(body))
        except Exception:
            raise MainnetError('submit_approval_invalid') from None
        if scope is not None:
            require(scope.txid == token['txid'] and scope.network == 'main'
                    and scope.provider == token['provider'] and scope.retry_unknown is False,
                    'submit_scope_mismatch')
        return True

    def _broadcaster(self, state):
        from .broadcast.client import BroadcastClient
        from .broadcast.journal import Journal as BroadcastJournal
        return BroadcastClient(network='main', provider='whatsonchain', transport=self.broadcast_transport,
            journal=BroadcastJournal(self.root/'broadcast.sqlite'), allow_submit=True,
            authorize=lambda scope: self._submit_authorized(state, scope))

    def _observe(self, session, state, result):
        valid = (result.get('network') == 'main' and result.get('provider') == 'whatsonchain'
                 and result.get('txid') == state['signed']['txid'] and result.get('state') in ('seen', 'mined')
                 and result.get('local_txid_recomputed') is True
                 and result.get('readback', {}).get('raw_txid_verified') is True)
        state['observation'] = result
        if valid:
            self.gate.settle(state['reservation_id'], state['signed']['txid'])
            state['stage'] = 'submitted'
        else:
            self.gate.uncertain(state['reservation_id'])
            state['stage'] = 'uncertain'
        session.save()
        return self._summary(state)

    def submit(self, workflow_id):
        from .signer import verify_signed_transaction
        from .signer.storage import consume
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            require('signed' in state, 'signed_transaction_required')
            receipt = self.gate.receipt(state['reservation_id'])
            if receipt['state'] in ('dispatching', 'uncertain', 'settled'):
                return self._summary(state)  # reconciliation only; never resend
            self._submit_authorized(state)
            signed = state['signed']
            require(verify_signed_transaction(state['signing_plan'], signed['signed_transaction_hex'],
                    self.config['wallet']['public_key_hex']), 'signature_invalid')
            self._fresh_inputs(state)
            consume(str(self.root/'submit-state'), state['submit_approval']['approval_id'], signed['txid'])
            outgoing = self.gate.begin_dispatch(state['reservation_id'])
            require(outgoing['raw_hex'] == signed['signed_transaction_hex'] and outgoing['txid'] == signed['txid'],
                    'stored_transaction_mismatch')
            state['stage'] = 'submitting'
            session.save()  # durable claim and journal before even the provider preflight GET
            try:
                result = self._broadcaster(state).submit(transaction_hex=outgoing['raw_hex'],
                    expected_txid=outgoing['txid'], transaction_network='main', submit=True,
                    retry_unknown=False, expected_outputs=[{k: p[k] for k in ('satoshis', 'locking_script_hex')}
                                                          for p in state['signing_plan']['outputs']])
            except Exception:
                result = {'state': 'ambiguous', 'network': 'main', 'provider': 'whatsonchain',
                          'txid': signed['txid'], 'readback': {}, 'local_txid_recomputed': False}
            return self._observe(session, state, result)

    def receipt(self, workflow_id):
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            if 'signed' not in state or self.gate.receipt(state['reservation_id'])['state'] not in (
                    'dispatching', 'uncertain', 'settled'):
                return self._summary(state)
            result = self._broadcaster(state).reconcile(state['signed']['txid'],
                        transaction_hex=state['signed']['signed_transaction_hex'])
            # A later unavailable provider never rolls back already settled accounting/receipt.
            if self.gate.receipt(state['reservation_id'])['state'] == 'settled':
                value = self._summary(state)
                value['latest_readback'] = result
                return value
            return self._observe(session, state, result)

    def review(self, workflow_id):
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            return dict(self._summary(state), signing_plan=state['signing_plan'], spend_plan=state['spend_plan'])

    def status(self, workflow_id):
        with self.journal.session() as session:
            return self._summary(self._state(session, workflow_id))
