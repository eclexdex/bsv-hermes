"""Resumable mainnet commitment publisher; no key or transport implementation."""
import hashlib
import json
import re
from dataclasses import asdict
from .errors import PublishError
from .contracts import (Prevout, FundingRequest, FundingSelection, BuildRequest,
                        SignRequest, AuthorizationRequest, SubmissionRequest,
                        SubmissionResult, LookupResult)
from .transaction import integer, hex_bytes, parse, skeleton, MAX_MONEY


def plan(text):
    if type(text) is not str or len(text) > 4096:
        raise PublishError('invalid_content')
    try:
        payload = text.encode('utf-8')
    except UnicodeError:
        raise PublishError('invalid_content') from None
    if len(payload) > 4096:
        raise PublishError('invalid_content')
    digest = hashlib.sha256(payload).hexdigest()
    return {'network': 'mainnet', 'format': 'sha256-op-return-v1',
            'digest_hex': digest, 'locking_script_hex': '006a20' + digest,
            'stage': 'planned', 'broadcast': False,
            'warning': 'A bare digest permits guessing low-entropy content. Publication is irreversible; no authorship or truth claim.'}


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def _identifier(value, prefix=''):
    pattern = re.escape(prefix) + '[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}'
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise PublishError('invalid_reference')
    return value


def _funding(state):
    value = state['funding']
    return FundingSelection(value['network'], tuple(Prevout(**p) for p in value['inputs']),
                            value['change_script_hex'], value['fee_sats'])


def _validate_funding(value, cap):
    if type(value) is not FundingSelection or value.network != 'mainnet' or type(value.inputs) is not tuple or not 1 <= len(value.inputs) <= 50:
        raise PublishError('invalid_funding')
    integer(value.fee_sats, 1, cap)
    # v1 accepts only standard P2PKH funding and wallet-owned change.
    if type(value.change_script_hex) is not str or re.fullmatch('76a914[0-9a-f]{40}88ac', value.change_script_hex) is None:
        raise PublishError('invalid_change_script')
    total, outpoints = 0, set()
    for p in value.inputs:
        if type(p) is not Prevout:
            raise PublishError('invalid_funding')
        hex_bytes(p.txid, 32, 32)
        if p.txid == '00' * 32:
            raise PublishError('invalid_funding')
        integer(p.vout, 0, 4294967294)
        total += integer(p.satoshis, 1, MAX_MONEY)
        if type(p.locking_script_hex) is not str or re.fullmatch('76a914[0-9a-f]{40}88ac', p.locking_script_hex) is None or p.outpoint in outpoints:
            raise PublishError('invalid_funding')
        outpoints.add(p.outpoint)
    if total > MAX_MONEY or total < value.fee_sats:
        raise PublishError('insufficient_funds')
    return total


def _validate_unsigned(raw, state):
    value = parse(raw)
    funding = _funding(state)
    total = _validate_funding(funding, state['intent']['max_spend_sats'])
    expected_inputs = [{'txid': p.txid, 'vout': p.vout, 'script_hex': '', 'sequence': 4294967295} for p in funding.inputs]
    outputs = [{'satoshis': 0, 'script_hex': state['intent']['locking_script_hex']}]
    if total > funding.fee_sats:
        outputs.append({'satoshis': total - funding.fee_sats, 'script_hex': funding.change_script_hex})
    if value['version'] != 1 or value['locktime'] != 0 or value['inputs'] != expected_inputs or value['outputs'] != outputs:
        raise PublishError('transaction_intent_mismatch')
    return value


def _validate_signed(raw, state):
    unsigned = _validate_unsigned(state['unsigned_tx_hex'], state)
    signed = parse(raw)
    if skeleton(signed) != skeleton(unsigned) or any(not p['script_hex'] for p in signed['inputs']):
        raise PublishError('signed_transaction_mismatch')
    return signed


def _summary(state):
    intent = state['intent']
    result = {'workflow_id': intent['workflow_id'], 'network': 'mainnet',
              'stage': state['stage'], 'digest_hex': intent['digest_hex'],
              'intent_digest': state['intent_digest'], 'max_spend_sats': intent['max_spend_sats'],
              'broadcast': None if state['stage'] in ('submitting', 'uncertain') else state['stage'] == 'submitted',
              'submission_attempted': state.get('submit_attempts', 0) > 0,
              'signed': 'signed_tx_hex' in state, 'consensus_validated': False,
              'last_error': state.get('last_error')}
    if 'funding' in state:
        result['fee_sats'] = state['funding']['fee_sats']
        result['input_count'] = len(state['funding']['inputs'])
    if 'txid' in state:
        result['txid'] = state['txid']
    if 'receipt' in state:
        result['receipt'] = dict(state['receipt'])
    return result


class Publisher:
    """No network/key defaults: the host injects reviewed mainnet adapters."""
    def __init__(self, journal, ports, *, hard_cap_sats):
        self.journal, self.ports = journal, ports
        self.hard_cap_sats = integer(hard_cap_sats, 1, MAX_MONEY)

    def _controls(self, execute, cap, approval_ref, submit, retry_submit):
        if execute is not True:
            raise PublishError('explicit_execution_required')
        integer(cap, 1, self.hard_cap_sats)
        _identifier(approval_ref, 'approval:')
        if type(submit) is not bool or type(retry_submit) is not bool or (retry_submit and not submit):
            raise PublishError('invalid_submit_control')
        if self.ports is None:
            raise PublishError('execution_not_configured')
        if getattr(self.ports.signer, 'local', None) is not True:
            raise PublishError('local_signer_required')

    def _validate_journal(self, session):
        """Detect corruption/inconsistent checkpoints before any outbound call.

        This is integrity checking, not authentication against a malicious owner.
        """
        stages = ('planned', 'funded', 'built', 'signed', 'submitting', 'uncertain', 'submitted')
        expected_reservations = {}
        try:
            if len(session.data['workflows']) > 256:
                raise ValueError()
            for wid, state in session.data['workflows'].items():
                _identifier(wid)
                if type(state) is not dict or set(state) - {'intent', 'intent_digest', 'stage', 'funding', 'unsigned_tx_hex', 'signed_tx_hex', 'txid', 'submit_attempts', 'receipt', 'submission_status', 'last_error'}:
                    raise ValueError()
                intent = state['intent']
                if type(intent) is not dict or set(intent) != {'version', 'network', 'workflow_id', 'wallet_ref', 'key_ref', 'max_spend_sats', 'digest_hex', 'locking_script_hex'}:
                    raise ValueError()
                if type(intent['version']) is not int or intent['version'] != 1 or intent['network'] != 'mainnet' or intent['workflow_id'] != wid or _hash(intent) != state['intent_digest']:
                    raise ValueError()
                _identifier(intent['wallet_ref'], 'wallet:')
                _identifier(intent['key_ref'], 'key:')
                integer(intent['max_spend_sats'], 1, MAX_MONEY)
                hex_bytes(intent['digest_hex'], 32, 32)
                if intent['locking_script_hex'] != '006a20' + intent['digest_hex'] or state['stage'] not in stages:
                    raise ValueError()
                rank = stages.index(state['stage'])
                for field, present in (('funding', rank >= 1), ('unsigned_tx_hex', rank >= 2),
                                       ('signed_tx_hex', rank >= 3), ('txid', rank >= 3),
                                       ('submit_attempts', rank >= 4), ('receipt', rank == 6)):
                    if (field in state) != present:
                        raise ValueError()
                if rank >= 1:
                    value = state['funding']
                    if type(value) is not dict or set(value) != {'network', 'inputs', 'change_script_hex', 'fee_sats'} or type(value['inputs']) not in (list, tuple) or not 1 <= len(value['inputs']) <= 50:
                        raise ValueError()
                    funding = _funding(state)
                    _validate_funding(funding, intent['max_spend_sats'])
                    for p in funding.inputs:
                        if p.outpoint in expected_reservations:
                            raise ValueError()
                        expected_reservations[p.outpoint] = wid
                if rank >= 2:
                    _validate_unsigned(state['unsigned_tx_hex'], state)
                if rank >= 3 and _validate_signed(state['signed_tx_hex'], state)['txid'] != state['txid']:
                    raise ValueError()
                if rank >= 4:
                    integer(state['submit_attempts'], 1, 1000000)
                if rank == 6:
                    status = state['receipt']['observed_status']
                    if state['receipt']['consensus_validated'] is not False or status not in ('mempool', 'confirmed') or state['receipt'] != {
                        'network': 'mainnet', 'txid': state['txid'], 'observed_status': status,
                        'verification': 'provider_readback', 'consensus_validated': False}:
                        raise ValueError()
                if 'submission_status' in state and state['submission_status'] not in ('accepted', 'already_known', 'rejected', 'unknown'):
                    raise ValueError()
                if 'last_error' in state and (type(state['last_error']) is not str or re.fullmatch('[a-z_]{1,64}', state['last_error']) is None):
                    raise ValueError()
            if expected_reservations != session.data['reservations']:
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError, IndexError):
            raise PublishError('journal_corrupt') from None

    def _state(self, session, workflow_id):
        _identifier(workflow_id)
        self._validate_journal(session)
        state = session.data['workflows'].get(workflow_id)
        if state is None:
            raise PublishError('workflow_not_found')
        return state

    def inspect(self, workflow_id):
        with self.journal.session() as session:
            return _summary(self._state(session, workflow_id))

    def execute(self, *, workflow_id, text, wallet_ref, key_ref, max_spend_sats,
                execute=False, approval_ref=None, submit=False, retry_submit=False):
        self._controls(execute, max_spend_sats, approval_ref, submit, retry_submit)
        _identifier(workflow_id)
        _identifier(wallet_ref, 'wallet:')
        _identifier(key_ref, 'key:')
        commitment = plan(text)
        intent = {'version': 1, 'network': 'mainnet', 'workflow_id': workflow_id,
                  'wallet_ref': wallet_ref, 'key_ref': key_ref, 'max_spend_sats': max_spend_sats,
                  'digest_hex': commitment['digest_hex'], 'locking_script_hex': commitment['locking_script_hex']}
        with self.journal.session() as session:
            self._validate_journal(session)
            state = session.data['workflows'].get(workflow_id)
            if state is None:
                if len(session.data['workflows']) >= 256:
                    raise PublishError('journal_full')
                state = {'intent': intent, 'intent_digest': _hash(intent), 'stage': 'planned'}
                session.data['workflows'][workflow_id] = state
                session.save()
            elif state['intent'] != intent:
                raise PublishError('idempotency_conflict')
            return self._advance(session, state, approval_ref, submit, retry_submit)

    def resume(self, *, workflow_id, max_spend_sats, execute=False, approval_ref=None,
               submit=False, retry_submit=False):
        self._controls(execute, max_spend_sats, approval_ref, submit, retry_submit)
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            if state['intent']['max_spend_sats'] != max_spend_sats:
                raise PublishError('spend_cap_changed')
            return self._advance(session, state, approval_ref, submit, retry_submit)

    @staticmethod
    def _call(error, fn, *args):
        try:
            return fn(*args)
        except Exception:
            raise PublishError(error) from None

    def _authorize(self, state, stage, approval_ref, raw=''):
        intent = state['intent']
        digest = _hash({'intent': intent, 'funding': state.get('funding'), 'transaction_hex': raw, 'stage': stage})
        funding = _funding(state) if 'funding' in state else None
        request = AuthorizationRequest(stage, intent['workflow_id'], 'mainnet', approval_ref,
            intent['wallet_ref'], intent['key_ref'], intent['max_spend_sats'], digest, raw,
            funding.inputs if funding else (), funding.fee_sats if funding else 0)
        allowed = self._call('authorization_failed', self.ports.authorization.authorize, request)
        if allowed is not True:
            raise PublishError('authorization_denied')
        return digest

    def _advance(self, session, state, approval_ref, submit, retry_submit):
        intent = state['intent']
        wid = intent['workflow_id']
        try:
            if state['stage'] == 'planned':
                self._authorize(state, 'select', approval_ref)
                request = FundingRequest(wid, 'mainnet', intent['locking_script_hex'], intent['wallet_ref'],
                    intent['key_ref'], intent['max_spend_sats'], tuple(sorted(session.data['reservations'])))
                funding = self._call('funding_failed', self.ports.funding.select, request)
                _validate_funding(funding, intent['max_spend_sats'])
                if any(p.outpoint in session.data['reservations'] for p in funding.inputs):
                    raise PublishError('input_reserved')
                state['funding'] = asdict(funding)
                for p in funding.inputs:
                    session.data['reservations'][p.outpoint] = wid
                state['stage'] = 'funded'
                session.save()
            if state['stage'] == 'funded':
                funding = _funding(state)
                request = BuildRequest(wid, 'mainnet', intent['locking_script_hex'], funding.inputs,
                                       funding.change_script_hex, funding.fee_sats)
                raw = self._call('build_failed', self.ports.builder.build, request)
                _validate_unsigned(raw, state)
                state.update(unsigned_tx_hex=raw, stage='built')
                session.save()
            if state['stage'] == 'built':
                raw = state['unsigned_tx_hex']
                digest = self._authorize(state, 'sign', approval_ref, raw)
                request = SignRequest(wid, 'mainnet', raw, _funding(state).inputs, intent['key_ref'],
                                      intent['max_spend_sats'], digest)
                signed = self._call('signing_failed', self.ports.signer.sign, request)
                tx = _validate_signed(signed, state)
                state.update(signed_tx_hex=signed, txid=tx['txid'], stage='signed')
                session.save()
            if state['stage'] in ('submitting', 'uncertain'):
                self._lookup(session, state)
                if state['stage'] != 'submitted' and not (submit and retry_submit):
                    return _summary(state)
            if state['stage'] in ('signed', 'uncertain') and submit:
                self._submit(session, state, approval_ref)
            if state['stage'] != 'uncertain':
                state.pop('last_error', None)
            session.save()
            return _summary(state)
        except PublishError as error:
            state['last_error'] = error.code
            session.save()
            raise

    def _submit(self, session, state, approval_ref):
        self._authorize(state, 'submit', approval_ref, state['signed_tx_hex'])
        state['stage'] = 'submitting'
        state['submit_attempts'] = state.get('submit_attempts', 0) + 1
        session.save()  # Durable BEFORE bytes can reach the network.
        request = SubmissionRequest(state['intent']['workflow_id'], 'mainnet', state['signed_tx_hex'],
                                    state['txid'], 'mainnet:' + state['txid'])
        try:
            response = self._call('submission_failed', self.ports.broadcaster.submit, request)
            if type(response) is not SubmissionResult or response.network != 'mainnet' or response.txid != state['txid'] or response.status not in ('accepted', 'already_known', 'rejected', 'unknown'):
                raise PublishError('invalid_submission_result')
            state['submission_status'] = response.status
        except PublishError as error:
            state.update(stage='uncertain', last_error=error.code)
            session.save()
            return
        # Even acceptance is not success until an exact txid read-back.
        self._lookup(session, state)

    def _lookup(self, session, state):
        try:
            response = self._call('lookup_failed', self.ports.broadcaster.lookup, state['txid'])
            if type(response) is not LookupResult or response.network != 'mainnet' or response.txid != state['txid'] or response.status not in ('mempool', 'confirmed', 'absent', 'unknown'):
                raise PublishError('invalid_lookup_result')
            if response.status in ('mempool', 'confirmed'):
                state['stage'] = 'submitted'
                state['receipt'] = {'network': 'mainnet', 'txid': state['txid'], 'observed_status': response.status,
                                    'verification': 'provider_readback', 'consensus_validated': False}
                state.pop('last_error', None)
            else:
                state.update(stage='uncertain', last_error='submission_unconfirmed')
        except PublishError as error:
            state.update(stage='uncertain', last_error=error.code)
        session.save()

    def reconcile(self, workflow_id):
        with self.journal.session() as session:
            state = self._state(session, workflow_id)
            if state['stage'] in ('submitting', 'uncertain'):
                if self.ports is None:
                    raise PublishError('execution_not_configured')
                self._lookup(session, state)
            return _summary(state)
