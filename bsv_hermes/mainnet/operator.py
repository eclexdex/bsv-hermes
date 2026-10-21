"""Operator-only administration, NEVER registered as Hermes tools.

This CLI/library does not authenticate a human. Protect this administration and
its authority directory with a separate trusted OS identity/channel. A process
with arbitrary same-UID file/shell access can bypass an in-process policy.
"""
import json
import os
from pathlib import Path

from .wallet import WalletStore
from .signer.storage import private_directory, read_private_json, path_parts
from .funding import PublicTarget
from . import spend_policy as policy


def _create_directory(path):
    # Reuse the wallet's descriptor-relative owner/mode/ancestor checks.
    with WalletStore(str(path))._directory(create=True):
        pass


def _create_json(directory, name, value):
    payload = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    with private_directory(str(directory)) as parent:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(payload); stream.flush(); os.fsync(fd)
            os.fsync(parent)
        finally:
            os.close(fd)
    if read_private_json(str(Path(directory)/name), len(payload) + 1) != value:
        raise ValueError('private_write_readback_failed')


def initialize(directory, authority_directory, *, total_cap_sat, max_fee_sat, fee_rate_sat_kb):
    """Fresh, create-only dedicated runtime. Does not obtain coins or approve a plan."""
    path_parts(directory); path_parts(authority_directory)
    root, authority = Path(directory), Path(authority_directory)
    policy.require(root != authority and root not in authority.parents and authority not in root.parents,
                   'separate_authority_directory_required')
    policy.integer(total_cap_sat, 'total_cap_sat', 1)
    policy.integer(max_fee_sat, 'max_fee_sat', 1, total_cap_sat)
    policy.integer(fee_rate_sat_kb, 'fee_rate_sat_kb', 1, 1000000)
    # Existing initialized or partially initialized locations are never replaced.
    policy.require(not root.exists() and not authority.exists(), 'fresh_directories_required')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    _create_directory(root); _create_directory(authority)
    for name in ('publish', 'signer-state', 'submit-state'):
        _create_directory(root/name)
    public = WalletStore(str(root/'wallet')).create(network='mainnet')
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    _create_json(authority, 'authority.json', {'schema': 'bsv-operator-authority-v1',
                 'private_key_hex': key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()})
    config = {'schema': 'bsv-mainnet-runtime-v1', 'wallet': public, 'approval_public_key_hex': public_key,
              'session_id': 'dedicated-publish', 'max_fee_sat': max_fee_sat, 'fee_rate_sat_kb': fee_rate_sat_kb}
    own_script = PublicTarget.from_wallet_metadata(public).locking_script_hex
    rules = {'version': 1, 'network': 'mainnet', 'total_cap_sat': total_cap_sat,
             'session_cap_sat': total_cap_sat, 'action_caps_sat': {'publish': max_fee_sat},
             'min_fee_sat': 1, 'max_fee_sat': max_fee_sat, 'min_fee_rate_sat_kb': fee_rate_sat_kb,
             'max_fee_rate_sat_kb': fee_rate_sat_kb*2, 'recipient_scripts': [],
             'change_scripts': [own_script], 'allow_data_outputs': True}
    ledger = policy.Authority.create(root/'budget.sqlite', rules)
    ledger.open_session(config['session_id'])
    _create_json(root, 'config.json', config)
    return WalletStore(str(root/'wallet')).address(expected_network='mainnet')


def _authority(directory, public_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    value = read_private_json(str(Path(directory)/'authority.json'))
    policy.require(set(value) == {'schema', 'private_key_hex'} and
                   value['schema'] == 'bsv-operator-authority-v1', 'authority_invalid')
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value['private_key_hex']))
    policy.require(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == public_key,
                   'authority_mismatch')
    return key


def approve_sign(directory, authority_directory, workflow_id, *, expected_digest, max_cost_sat):
    from .runtime import Runtime, require
    from .signer.core import canonical
    import secrets
    import time
    runtime = Runtime(directory)
    with runtime.journal.session() as session:
        state = runtime._state(session, workflow_id)
        require(state['stage'] == 'built' and 'sign_approval' not in state, 'already_claimed')
        require(expected_digest == state['signing_digest'], 'review_digest_mismatch')
        policy.integer(max_cost_sat, 'max_cost_sat', 1, runtime.config['max_fee_sat'])
        require(state['spend_plan']['fee_sat'] <= max_cost_sat, 'operator_cap_exceeded')
        key = _authority(authority_directory, runtime.config['approval_public_key_hex'])
        now = int(time.time())
        token = {'schema': 'bsv-signing-approval-v1', 'intent': 'sign-bsv-transaction',
                 'wallet_id': runtime.config['wallet']['wallet_id'], 'network': 'mainnet',
                 'plan_digest': state['signing_digest'], 'approval_id': secrets.token_hex(32),
                 'issued_at': now, 'expires_at': now+300}
        token['signature_hex'] = key.sign(b'bsv-signing-approval-v1\0' + canonical(token)).hex()
        policy.Authority(runtime.gate.db_path).approve(runtime.config['session_id'], state['spend_plan'],
                     state['spend_digest'], expires_at=now+300)
        state['sign_approval'] = token
        session.save()
        return {'approved': 'sign_only', 'signing_digest': state['signing_digest'], 'expires_at': now+300,
                'max_cost_sat': max_cost_sat, 'broadcast_approved': False}


def approve_submit(directory, authority_directory, workflow_id, *, expected_txid):
    from .runtime import Runtime, require
    from .signer import verify_signed_transaction
    from .signer.core import canonical
    import secrets
    import time
    runtime = Runtime(directory)
    with runtime.journal.session() as session:
        state = runtime._state(session, workflow_id)
        require(state['stage'] == 'signed' and 'submit_approval' not in state, 'signed_unsubmitted_required')
        require(expected_txid == state['signed']['txid'], 'review_txid_mismatch')
        require(verify_signed_transaction(state['signing_plan'], state['signed']['signed_transaction_hex'],
                runtime.config['wallet']['public_key_hex']), 'signature_invalid')
        key = _authority(authority_directory, runtime.config['approval_public_key_hex'])
        now = int(time.time())
        token = {'schema': 'bsv-submit-approval-v1', 'network': 'mainnet', 'provider': 'whatsonchain',
                 'wallet_id': runtime.config['wallet']['wallet_id'], 'signing_digest': state['signing_digest'],
                 'txid': expected_txid, 'approval_id': secrets.token_hex(32), 'issued_at': now, 'expires_at': now+300}
        token['signature_hex'] = key.sign(b'bsv-submit-approval-v1\0' + canonical(token)).hex()
        state['submit_approval'] = token
        session.save()
        return {'approved': 'submit_only', 'txid': expected_txid, 'expires_at': now+300, 'retry_allowed': False}
