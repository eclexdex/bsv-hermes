"""Local, offline signer. Trusted host configuration is never a tool argument."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
import re
import time

from . import storage, wire

ERRORS = {
    'invalid_plan': 'Signing plan failed validation.',
    'invalid_config': 'Trusted signer configuration is invalid.',
    'approval_rejected': 'Authentic, unexpired approval for this exact signing intent is required.',
    'approval_used': 'This approval was already consumed.',
    'unsafe_storage': 'Private signer storage failed ownership, type or permission checks.',
    'wallet_mismatch': 'The dedicated wallet does not match the signing plan.',
    'wallet_unavailable': 'The reviewed local wallet package is required.',
    'sdk_unavailable': 'Pinned SDK and native signing backend are required.',
    'verification_failed': 'Independent signature or transaction verification failed.',
    'signing_failed': 'The local signing operation failed; no private details are returned.',
}


class SignerError(ValueError):
    def __init__(self, code):
        self.code = code if code in ERRORS else 'signing_failed'
        super().__init__(ERRORS[self.code])


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _bounded_request(value):
    """Bound exact JSON types/ASCII size before snapshot serialization.

    Do not let json.dumps normalize tuples, subclasses or non-string keys into
    an apparently valid approved plan. This is not semantic plan validation.
    """
    remaining, nodes = 2200000, 0

    def visit(item, depth=0):
        nonlocal remaining, nodes
        nodes += 1
        if nodes > 20000 or depth > 16:
            raise SignerError('invalid_plan')
        kind = type(item)
        if kind is str:
            if len(item) > min(200000, remaining) or not item.isascii():
                raise SignerError('invalid_plan')
            remaining -= 2 + len(item)
            remaining -= sum(1 if c in '\"\\\\\b\f\n\r\t' else 5 if ord(c) < 32 or ord(c) == 127 else 0 for c in item)
        elif kind in (dict, list):
            if len(item) > 20000 - nodes:
                raise SignerError('invalid_plan')
            remaining -= 2 + max(0, len(item) - 1)
            if kind is dict:
                remaining -= len(item)
                for key, child in item.items():
                    if type(key) is not str:
                        raise SignerError('invalid_plan')
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif kind is bool:
            remaining -= 4 if item else 5
        elif item is None:
            remaining -= 4
        elif kind is int and -9223372036854775808 <= item <= 9223372036854775807:
            remaining -= len(str(item))
        else:
            raise SignerError('invalid_plan')
        if remaining < 0:
            raise SignerError('invalid_plan')

    visit(value)


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise SignerError('invalid_plan')


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise SignerError('invalid_plan')


def _hex(value, length=None, limit=200000):
    if (type(value) is not str or len(value) > limit or len(value) % 2
            or (length is not None and len(value) != length * 2)
            or re.fullmatch('[0-9a-f]+', value) is None):
        raise SignerError('invalid_plan')


def _plan(plan):
    _object(plan, ('schema', 'network', 'wallet_id', 'operation', 'version', 'lock_time', 'sighash',
                   'inputs', 'outputs', 'payment_satoshis', 'fee_satoshis', 'unsigned_transaction_hex'))
    if plan['schema'] != 'bsv-signing-plan-v1' or plan['network'] not in ('mainnet', 'testnet'):
        raise SignerError('invalid_plan')
    if plan['operation'] not in ('payment', 'publish'):
        raise SignerError('invalid_plan')
    _hex(plan['wallet_id'], 32)
    if type(plan['inputs']) is not list or not 1 <= len(plan['inputs']) <= 64:
        raise SignerError('invalid_plan')
    if type(plan['outputs']) is not list or not 1 <= len(plan['outputs']) <= 64:
        raise SignerError('invalid_plan')
    for field, low, high in [('version', 1, 1), ('lock_time', 0, 0), ('sighash', 65, 65),
                             ('payment_satoshis', 0, 2100000000000000), ('fee_satoshis', 0, 2100000000000000)]:
        _integer(plan[field], low, high)
    seen = set()
    for item in plan['inputs']:
        _object(item, ('txid', 'vout', 'satoshis', 'locking_script_hex', 'sequence', 'source_transaction_hex'))
        _hex(item['txid'], 32)
        _hex(item['locking_script_hex'], 25)
        _hex(item['source_transaction_hex'])
        _integer(item['vout'], 0, 0xffffffff)
        _integer(item['sequence'], 0xffffffff, 0xffffffff)
        _integer(item['satoshis'], 1, 2100000000000000)
        _p2pkh(item['locking_script_hex'])
        outpoint = (item['txid'], item['vout'])
        if outpoint in seen or outpoint == ('00' * 32, 0xffffffff):
            raise SignerError('invalid_plan')
        seen.add(outpoint)
        source_raw = bytes.fromhex(item['source_transaction_hex'])
        source = wire.parse(source_raw)
        if wire.hash256(source_raw)[::-1].hex() != item['txid'] or item['vout'] >= len(source['outputs']):
            raise SignerError('invalid_plan')
        source_output = source['outputs'][item['vout']]
        if (source_output['satoshis'] != item['satoshis']
                or source_output['locking_script_hex'] != item['locking_script_hex']):
            raise SignerError('invalid_plan')
    for item in plan['outputs']:
        _object(item, ('role', 'address', 'satoshis', 'locking_script_hex'))
        _hex(item['locking_script_hex'])
        _integer(item['satoshis'], 0, 2100000000000000)
        if item['role'] in ('recipient', 'change'):
            _p2pkh(item['locking_script_hex'])
            if item['satoshis'] == 0 or _address_script(item['address'], plan['network']) != item['locking_script_hex']:
                raise SignerError('invalid_plan')
        elif item['role'] == 'data':
            if item['satoshis'] != 0 or item['address'] is not None:
                raise SignerError('invalid_plan')
            _data_script(item['locking_script_hex'])
        else:
            raise SignerError('invalid_plan')
    roles = [o['role'] for o in plan['outputs']]
    if roles.count('change') > 1 or ('change' in roles and roles[-1] != 'change'):
        raise SignerError('invalid_plan')
    if ((plan['operation'] == 'payment' and ('recipient' not in roles or 'data' in roles))
            or (plan['operation'] == 'publish' and (roles.count('data') != 1 or 'recipient' in roles))):
        raise SignerError('invalid_plan')
    if (sum(i['satoshis'] for i in plan['inputs']) > 2100000000000000
            or sum(o['satoshis'] for o in plan['outputs']) > 2100000000000000):
        raise SignerError('invalid_plan')
    _hex(plan['unsigned_transaction_hex'])
    if wire.serialize(plan).hex() != plan['unsigned_transaction_hex']:
        raise SignerError('invalid_plan')
    if len(bytes.fromhex(plan['unsigned_transaction_hex'])) + 108 * len(plan['inputs']) > wire.MAX_BYTES:
        raise SignerError('invalid_plan')
    if sum(i['satoshis'] for i in plan['inputs']) - sum(o['satoshis'] for o in plan['outputs']) != plan['fee_satoshis']:
        raise SignerError('invalid_plan')
    if sum(o['satoshis'] for o in plan['outputs'] if o['role'] == 'recipient') != plan['payment_satoshis']:
        raise SignerError('invalid_plan')
    if len(canonical(plan)) > 2097152:
        raise SignerError('invalid_plan')
    return plan


def _p2pkh(script):
    _hex(script, 25)
    if not script.startswith('76a914') or not script.endswith('88ac'):
        raise SignerError('invalid_plan')


def _address_script(address, network):
    if type(address) is not str or not 26 <= len(address) <= 35:
        raise SignerError('invalid_plan')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = 0
    for character in address:
        value = value * 58 + alphabet.index(character)
    raw = b'\0' * (len(address) - len(address.lstrip('1'))) + value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if (len(raw) != 25 or raw[0] != (0 if network == 'mainnet' else 111)
            or wire.hash256(raw[:-4])[:4] != raw[-4:]):
        raise SignerError('invalid_plan')
    return '76a914' + raw[1:21].hex() + '88ac'


def _data_script(script_hex):
    raw = bytes.fromhex(script_hex)
    if not 2 <= len(raw) <= 8192 or raw[:2] != b'\x00\x6a':
        raise SignerError('invalid_plan')
    cursor = 2
    while cursor < len(raw):
        opcode = raw[cursor]
        cursor += 1
        if opcode <= 75:
            length = opcode
        elif opcode in (76, 77):
            width = 1 if opcode == 76 else 2
            if cursor + width > len(raw):
                raise SignerError('invalid_plan')
            length = int.from_bytes(raw[cursor:cursor + width], 'little')
            cursor += width
            if length < (76 if opcode == 76 else 256):
                raise SignerError('invalid_plan')
        else:
            raise SignerError('invalid_plan')
        cursor += length
        if cursor > len(raw):
            raise SignerError('invalid_plan')


def plan_digest(plan):
    try:
        return hashlib.sha256(b'bsv-signing-plan-v1\0' + canonical(_plan(plan))).hexdigest()
    except SignerError:
        raise
    except Exception:
        raise SignerError('invalid_plan') from None


@dataclass(frozen=True, repr=False)
class SignerConfig:
    key_file: str
    state_directory: str
    network: str
    wallet_id: str
    approval_public_key_hex: str
    max_fee_satoshis: int
    max_payment_satoshis: int


def _sdk():
    try:
        if importlib.metadata.version('bsv-sdk') != '2.4.0' or importlib.metadata.version('cryptography') != '48.0.0':
            raise RuntimeError()
        import bsv
        from bsv.native import native_status
        from bsv.keys import _CRYPTO_BACKEND
        if native_status().get('backend') != 'libsecp256k1' or _CRYPTO_BACKEND != 'native':
            raise RuntimeError()
        return bsv
    except Exception:
        raise SignerError('sdk_unavailable') from None


def _approval(approval, digest, config):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        _object(approval, ('schema', 'intent', 'wallet_id', 'network', 'plan_digest',
                           'approval_id', 'issued_at', 'expires_at', 'signature_hex'))
        if (approval['schema'] != 'bsv-signing-approval-v1' or approval['intent'] != 'sign-bsv-transaction'
                or approval['wallet_id'] != config.wallet_id or approval['network'] != config.network
                or approval['plan_digest'] != digest):
            raise ValueError()
        _hex(approval['approval_id'], 32)
        _hex(approval['signature_hex'], 64)
        _integer(approval['issued_at'], 0, 0x7fffffffffffffff)
        _integer(approval['expires_at'], 0, 0x7fffffffffffffff)
        now = int(time.time())
        if not approval['issued_at'] <= now < approval['expires_at'] <= approval['issued_at'] + 300:
            raise ValueError()
        body = {k: v for k, v in approval.items() if k != 'signature_hex'}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(config.approval_public_key_hex)).verify(
            bytes.fromhex(approval['signature_hex']), b'bsv-signing-approval-v1\0' + canonical(body))
    except Exception:
        raise SignerError('approval_rejected') from None


def verify_signed_transaction(plan, signed_transaction_hex, public_key_hex):
    try:
        _plan(plan)
        _hex(signed_transaction_hex)
        _hex(public_key_hex, 33)
        return wire.verify(plan, signed_transaction_hex, public_key_hex)
    except Exception:
        return False


@contextmanager
def _wallet(config):
    try:
        from ..wallet import WalletStore, WalletError
    except ImportError:
        raise SignerError('wallet_unavailable') from None
    lease = WalletStore(config.key_file.rsplit('/', 1)[0]).signing_key(
        expected_network=config.network, expected_wallet_id=config.wallet_id)
    try:
        key = lease.__enter__()
    except WalletError as exc:
        code = exc.code if exc.code in ('unsafe_storage', 'sdk_unavailable') else 'wallet_mismatch'
        raise SignerError(code) from None
    try:
        yield key, key.public_key().hex(compressed=True)
    finally:
        # Invalidate the canonical lease on every path. Passing no body exception
        # preserves our sanitized errors instead of the wallet wrapper recoding
        # them as storage_error. No secret is copied, serialized or returned.
        lease.__exit__(None, None, None)


class LocalSigner:
    def __init__(self, config):
        if type(config) is not SignerConfig:
            raise SignerError('invalid_config')
        try:
            parts = storage.path_parts(config.key_file)
            if len(parts) < 2 or parts[-1] != 'wallet.json':
                raise ValueError()
            storage.path_parts(config.state_directory)
            _hex(config.wallet_id, 32)
            _hex(config.approval_public_key_hex, 32)
            if config.network not in ('mainnet', 'testnet'):
                raise ValueError()
            _integer(config.max_fee_satoshis, 0, 2100000000000000)
            _integer(config.max_payment_satoshis, 0, 2100000000000000)
        except Exception:
            raise SignerError('invalid_config') from None
        self._config = config

    def sign(self, plan, approval):
        try:
            # JSON snapshot: caller mutation cannot change the approved bytes mid-sign.
            _bounded_request({'plan': plan, 'approval': approval})
            plan = json.loads(canonical(plan))
            approval = json.loads(canonical(approval))
            digest = plan_digest(plan)
            cfg = self._config
            if plan['network'] != cfg.network or plan['wallet_id'] != cfg.wallet_id:
                raise SignerError('wallet_mismatch')
            if plan['fee_satoshis'] > cfg.max_fee_satoshis or plan['payment_satoshis'] > cfg.max_payment_satoshis:
                raise SignerError('invalid_plan')
            _approval(approval, digest, cfg)
            sdk = _sdk()
            with _wallet(cfg) as (key, public):
                return self._sign_approved(plan, approval, digest, sdk, key, public)
        except SignerError:
            raise
        except Exception:
            raise SignerError('signing_failed') from None

    def _sign_approved(self, plan, approval, digest, sdk, key, public):
        cfg = self._config
        pubhash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(public)).digest()).hexdigest()
        own_script = '76a914' + pubhash + '88ac'
        if (any(i['locking_script_hex'] != own_script for i in plan['inputs'])
                or any(o['locking_script_hex'] != own_script for o in plan['outputs'] if o['role'] == 'change')):
            raise SignerError('wallet_mismatch')
        tx_inputs = []
        for item in plan['inputs']:
            inp = sdk.TransactionInput(source_txid=item['txid'], source_output_index=item['vout'],
                                       sequence=item['sequence'], sighash=sdk.SIGHASH.ALL_FORKID,
                                       unlocking_script_template=sdk.P2PKH().unlock(key))
            inp.satoshis = item['satoshis']
            inp.locking_script = sdk.Script(bytes.fromhex(item['locking_script_hex']))
            tx_inputs.append(inp)
        tx_outputs = [sdk.TransactionOutput(locking_script=sdk.Script(bytes.fromhex(o['locking_script_hex'])),
                                           satoshis=o['satoshis'], change=False) for o in plan['outputs']]
        tx = sdk.Transaction(tx_inputs=tx_inputs, tx_outputs=tx_outputs,
                             version=plan['version'], locktime=plan['lock_time'])
        if tx.hex() != plan['unsigned_transaction_hex']:
            raise SignerError('verification_failed')
        for i in range(len(tx_inputs)):
            if tx.preimage(i) != wire.preimage(plan, i):
                raise SignerError('verification_failed')
        _approval(approval, digest, cfg)
        try:
            storage.consume(cfg.state_directory, approval['approval_id'], digest)
        except storage.AlreadyConsumed:
            raise SignerError('approval_used') from None
        except storage.StorageError:
            raise SignerError('unsafe_storage') from None
        tx.sign()
        signed_hex = tx.hex()
        if not verify_signed_transaction(plan, signed_hex, public):
            raise SignerError('verification_failed')
        return {'schema': 'bsv-signed-transaction-v1', 'network': cfg.network, 'wallet_id': cfg.wallet_id,
                'plan_digest': digest, 'approval_id': approval['approval_id'], 'signed_transaction_hex': signed_hex,
                'txid': wire.hash256(bytes.fromhex(signed_hex))[::-1].hex(), 'fee_satoshis': plan['fee_satoshis'],
                'payment_satoshis': plan['payment_satoshis'], 'signed': True, 'broadcast': False}
