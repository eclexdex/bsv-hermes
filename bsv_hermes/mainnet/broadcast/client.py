"""Bounded, custody-free BSV submission and reconciliation.

Structural validation is not consensus validation or proof of signing authority.
"""
from dataclasses import dataclass
import hashlib
import re
import json
import math
import time
from .endpoints import endpoint
from .transport import HTTPTransport, TransportError
from .journal import Journal, JournalError

MAX_TX_BYTES = 100000
MAX_SCRIPT_BYTES = 10000
MAX_IO = 1000
MAX_MONEY = 2100000000000000


class InputError(ValueError):
    """Invalid local intent. Messages never echo supplied transaction data."""


def strict_hex(value, maximum, exact=None):
    if (type(value) is not str or not value or len(value) > maximum * 2
            or len(value) % 2 or re.fullmatch(r'[0-9a-fA-F]+', value) is None
            or (exact is not None and len(value) != exact * 2)):
        raise InputError('invalid hexadecimal input')
    return bytes.fromhex(value)


def txid_for(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def checked_txid(value):
    strict_hex(value, 32, 32)
    # Do not repair whitespace, prefixes, malformed identifiers, or casing.
    if value != value.lower():
        raise InputError('transaction identifier must be lowercase hexadecimal')
    return value


def checked_network(value):
    if type(value) is not str or value not in ('main', 'test'):
        raise InputError('network must be main or test')
    return value


class _Reader:
    def __init__(self, raw):
        self.raw, self.pos = raw, 0

    def take(self, size):
        if size < 0 or size > len(self.raw) - self.pos:
            raise InputError('truncated transaction')
        result = self.raw[self.pos:self.pos + size]
        self.pos += size
        return result

    def number(self, width):
        return int.from_bytes(self.take(width), 'little')

    def compact(self):
        marker = self.number(1)
        if marker < 253:
            return marker
        value = self.number({253: 2, 254: 4, 255: 8}[marker])
        if value < {253: 253, 254: 65536, 255: 4294967296}[marker]:
            raise InputError('noncanonical CompactSize')
        return value

    def script(self):
        size = self.compact()
        if size > MAX_SCRIPT_BYTES:
            raise InputError('script exceeds local policy')
        return self.take(size)


def transaction_outputs(raw):
    r = _Reader(raw)
    r.take(4)
    count = r.compact()
    if not 1 <= count <= MAX_IO:
        raise InputError('input count or serialization not supported')
    previous = set()
    for _ in range(count):
        outpoint = r.take(36)
        if outpoint[:32] == bytes(32) or outpoint in previous:
            raise InputError('coinbase or repeated input is not supported')
        previous.add(outpoint)
        r.script()
        r.take(4)
    count = r.compact()
    if not 1 <= count <= MAX_IO:
        raise InputError('output count exceeds local policy')
    outputs = [(r.number(8), r.script()) for _ in range(count)]
    r.take(4)
    if r.pos != len(raw):
        raise InputError('trailing bytes or unsupported serialization')
    if any(amount > MAX_MONEY for amount, _ in outputs) or sum(x[0] for x in outputs) > MAX_MONEY:
        raise InputError('output amount exceeds local policy')
    return outputs


def address_script(address, network):
    """Only legacy Base58Check P2PKH. No inferred network from raw Script."""
    checked_network(network)
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if type(address) is not str or not 26 <= len(address) <= 35:
        raise InputError('invalid P2PKH address')
    number = 0
    for char in address:
        if char not in alphabet:
            raise InputError('invalid P2PKH address')
        number = number * 58 + alphabet.index(char)
    data = bytes(len(address) - len(address.lstrip('1'))) + number.to_bytes((number.bit_length() + 7) // 8, 'big')
    if (len(data) != 25 or data[0] != {'main': 0, 'test': 111}[network]
            or hashlib.sha256(hashlib.sha256(data[:21]).digest()).digest()[:4] != data[21:]):
        raise InputError('P2PKH address checksum or network mismatch')
    return b'\x76\xa9\x14' + data[1:21] + b'\x88\xac'


@dataclass(frozen=True)
class Intent:
    raw: bytes
    txid: str
    network: str
    output_satoshis: int
    output_count: int


def validate_intent(*, network, transaction_hex, expected_txid, transaction_network,
                    expected_outputs):
    checked_network(network)
    if checked_network(transaction_network) != network:
        raise InputError('declared transaction network does not match client')
    raw = strict_hex(transaction_hex, MAX_TX_BYTES)
    txid = txid_for(raw)
    if checked_txid(expected_txid) != txid:
        raise InputError('transaction bytes do not match expected txid')
    outputs = transaction_outputs(raw)
    if type(expected_outputs) is not list or len(expected_outputs) != len(outputs):
        raise InputError('expected outputs must cover every output in order')
    for expected, (amount, script) in zip(expected_outputs, outputs):
        if (type(expected) is not dict or set(expected) - {'satoshis', 'locking_script_hex', 'address'}
                or not {'satoshis', 'locking_script_hex'} <= set(expected)
                or type(expected['satoshis']) is not int or expected['satoshis'] != amount):
            raise InputError('output intent mismatch')
        text = expected['locking_script_hex']
        wanted = b'' if text == '' else strict_hex(text, MAX_SCRIPT_BYTES)
        if wanted != script:
            raise InputError('output locking script mismatch')
        if 'address' in expected and address_script(expected['address'], network) != script:
            raise InputError('output address does not match locking script')
    return Intent(raw, txid, network, sum(x[0] for x in outputs), len(outputs))


class GateError(PermissionError):
    """No submission authority. No network I/O has been performed."""


@dataclass(frozen=True)
class ApprovalScope:
    txid: str
    network: str
    provider: str
    size_bytes: int
    output_satoshis: int
    output_count: int
    retry_unknown: bool


def _json(body):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    def invalid_constant(value):
        raise ValueError('invalid JSON constant')
    return json.loads(body.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid_constant)


def _observation(state, **fields):
    return dict(state=state, provider_reported_txid_match=False,
                raw_txid_verified=False, inclusion_verified=False, **fields)


def _status_data(data, protocol, txid):
    if type(data) is not dict or data.get('txid') != txid:
        return _observation('identity_mismatch', http_status=200)
    result = _observation('seen', http_status=200)
    result['provider_reported_txid_match'] = True
    if protocol == 'woc':
        confirmations = data.get('confirmations', 0)
        if type(confirmations) is not int or not 0 <= confirmations <= 100000000:
            return _observation('protocol_error')
        result['confirmations_reported'] = confirmations
        if confirmations > 0:
            result['state'] = 'mined'
        block_hash, height = data.get('blockhash'), data.get('blockheight')
    else:
        status = data.get('txStatus')
        states = {'MINED': 'mined', 'IMMUTABLE': 'mined',
                  'REJECTED': 'rejected', 'DOUBLE_SPEND_ATTEMPTED': 'conflict',
                  'SEEN_ON_NETWORK': 'accepted', 'SEEN_MULTIPLE_NODES': 'accepted',
                  'ACCEPTED_BY_NETWORK': 'accepted',
                  'RECEIVED': 'processing', 'STORED': 'processing',
                  'ANNOUNCED_TO_NETWORK': 'processing', 'REQUESTED_BY_NETWORK': 'processing',
                  'SENT_TO_NETWORK': 'processing', 'QUEUED': 'processing',
                  'PENDING_RETRY': 'processing', 'STUMP_PROCESSING': 'processing',
                  'SEEN_IN_ORPHAN_MEMPOOL': 'processing', 'UNKNOWN': 'unknown'}
        if type(status) is not str or status not in states:
            return _observation('protocol_error')
        result['state'], result['provider_status'] = states[status], status
        block_hash, height = data.get('blockHash'), data.get('blockHeight')
    if result['state'] == 'mined':
        if (type(block_hash) is not str or re.fullmatch(r'[0-9a-f]{64}', block_hash) is None
                or type(height) is not int or not 0 <= height <= 100000000):
            return _observation('protocol_error')
        result.update(block_hash=block_hash, block_height=height)
    return result


def _post_data(response, protocol, txid):
    result = {'http_status': response.status, 'state': 'ambiguous', 'txid_match': False}
    plain = response.body.decode('ascii', errors='replace')
    try:
        # WoC documents text/plain: an all-decimal txid must not become a JSON
        # number and lose its identity. Preserve the exact token before parsing.
        data = plain if protocol == 'woc' and re.fullmatch(r'[0-9a-f]{64}', plain) else _json(response.body)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        data = plain
    claimed = data if type(data) is str and re.fullmatch(r'[0-9a-f]{64}', data) else (
        data.get('txid') if type(data) is dict else None)
    if claimed is not None and claimed != txid:
        result['state'] = 'identity_mismatch'
        return result
    result['txid_match'] = claimed == txid
    if protocol != 'woc' and (response.status in (400, 422) or 460 <= response.status <= 499):
        result['state'] = 'rejected'
    elif 200 <= response.status < 300 and claimed == txid:
        if protocol == 'woc':
            result['state'] = 'acknowledged'
        else:
            observed = _status_data(data, protocol, txid)
            result['state'] = observed['state']
    return result


def _combined_state(readback, row, post=None):
    if any(evidence and evidence['state'] == 'identity_mismatch' for evidence in (post, row)):
        return 'identity_mismatch'
    if readback['state'] not in ('not_found', 'unavailable', 'protocol_error', 'unknown'):
        return readback['state']
    for evidence in (post, row):
        if evidence and evidence['state'] in ('rejected', 'conflict', 'identity_mismatch'):
            return evidence['state']
    return 'ambiguous' if row else readback['state']


class BroadcastClient:
    def __init__(self, *, network, provider='whatsonchain', transport=None,
                 allow_submit=False, journal=None, authorize=None, total_timeout=30):
        self.network = checked_network(network)
        self.endpoint = endpoint(provider, network)
        if type(allow_submit) is not bool:
            raise InputError('allow_submit must be boolean')
        if (type(total_timeout) not in (int, float) or not math.isfinite(total_timeout)
                or not 0.5 <= total_timeout <= 30):
            raise InputError('total timeout outside local policy')
        self.transport = transport if transport is not None else HTTPTransport()
        self.allow_submit, self.journal, self.authorize = allow_submit, journal, authorize
        self.total_timeout = total_timeout

    def _request(self, method, url, deadline, body=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError('deadline')
        return self.transport.request(method, url, body=body, timeout=remaining)

    def _read(self, txid, deadline):
        try:
            response = self._request('GET', self.endpoint.status_url(txid), deadline)
            if response.status == 404:
                return _observation('not_found', http_status=404)
            if response.status != 200:
                return _observation('unavailable', http_status=response.status)
            observation = _status_data(_json(response.body), self.endpoint.protocol, txid)
            if observation['state'] in ('protocol_error', 'identity_mismatch') or self.endpoint.protocol != 'woc':
                return observation
            raw_response = self._request('GET', self.endpoint.raw_url(txid), deadline)
            if raw_response.status != 200:
                return _observation('unavailable', http_status=raw_response.status)
            raw = strict_hex(raw_response.body.decode('ascii'), MAX_TX_BYTES)
            if txid_for(raw) != txid:
                return _observation('identity_mismatch', http_status=200)
            observation['raw_txid_verified'] = True
            return observation
        except TransportError as error:
            return _observation('unavailable', error=error.code)
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            return _observation('protocol_error')

    def reconcile(self, txid, *, transaction_hex=None):
        txid = checked_txid(txid)
        recomputed = False
        if transaction_hex is not None:
            if txid_for(strict_hex(transaction_hex, MAX_TX_BYTES)) != txid:
                raise InputError('readback intent txid mismatch')
            recomputed = True
        row = self.journal.get(self.network, txid) if self.journal else None
        if row and row['provider'] != self.endpoint.provider:
            raise GateError('attempt is pinned to another provider; reconcile there')
        result = self._read(txid, time.monotonic() + self.total_timeout)
        if self.journal:
            self.journal.observe(self.network, txid, self.endpoint.provider, result['state'])
            row = self.journal.get(self.network, txid)
        return dict(txid=txid, network=self.network, provider=self.endpoint.provider,
                    state=_combined_state(result, row), readback=result, local_txid_recomputed=recomputed,
                    post_attempts_this_call=0, post_attempts_total=row['attempts'] if row else 0,
                    inclusion_verified=False)

    def _result(self, intent, readback, attempts=0, post=None, reason=None):
        row = self.journal.get(self.network, intent.txid)
        state = _combined_state(readback, row, post)
        result = dict(txid=intent.txid, network=self.network, provider=self.endpoint.provider,
                      state=state, readback=readback, local_txid_recomputed=True,
                      post_attempts_this_call=attempts, post_attempts_total=row['attempts'] if row else 0,
                      post_response=post, inclusion_verified=False, reason=reason)
        return result

    def submit(self, *, transaction_hex, expected_txid, transaction_network,
               expected_outputs, submit=False, retry_unknown=False):
        # These gates precede all GETs as well as POSTs. The callback must be
        # supplied by trusted host code; a model-written boolean is not consent.
        if (self.allow_submit is not True or submit is not True or not callable(self.authorize)
                or not isinstance(self.journal, Journal)):
            raise GateError('submission requires host enablement, explicit submit, journal and external authorization')
        if type(retry_unknown) is not bool:
            raise InputError('retry_unknown must be boolean')
        intent = validate_intent(network=self.network, transaction_hex=transaction_hex,
                                 expected_txid=expected_txid, transaction_network=transaction_network,
                                 expected_outputs=expected_outputs)
        scope = ApprovalScope(intent.txid, intent.network, self.endpoint.provider, len(intent.raw),
                              intent.output_satoshis, intent.output_count, retry_unknown)
        if self.authorize(scope) is not True:
            raise GateError('exact transaction was not authorized by the host')
        row = self.journal.get(self.network, intent.txid)
        if row and row['provider'] != self.endpoint.provider:
            raise GateError('attempt is pinned to another provider; reconcile there')
        deadline = time.monotonic() + self.total_timeout
        preflight = self._read(intent.txid, deadline)
        if preflight['state'] != 'not_found':
            self.journal.observe(self.network, intent.txid, self.endpoint.provider, preflight['state'])
            return self._result(intent, preflight, reason='preflight_readback')
        if not self.journal.claim(self.network, intent.txid, self.endpoint.provider, retry=retry_unknown):
            return self._result(intent, preflight, reason='already_attempted_reconcile_only')
        post = None
        try:
            key = 'txhex' if self.endpoint.protocol == 'woc' else 'rawTx'
            body = json.dumps({key: intent.raw.hex()}, separators=(',', ':')).encode()
            response = self._request('POST', self.endpoint.submit_url, deadline, body)
            post = _post_data(response, self.endpoint.protocol, intent.txid)
        except TransportError as error:
            post = {'state': 'ambiguous', 'error': error.code, 'txid_match': False}
        readback = self._read(intent.txid, deadline)
        state = _combined_state(readback, {'state': 'ambiguous'}, post)
        try:
            self.journal.finish(self.network, intent.txid, state)
            result = self._result(intent, readback, attempts=1, post=post)
            result['journal_ok'] = True
            return result
        except JournalError:
            # The POST may have succeeded. Preserve its exact identity even if
            # local disk state fails; never make the caller reconstruct intent.
            return dict(txid=intent.txid, network=self.network, provider=self.endpoint.provider,
                        state='ambiguous', readback=readback, local_txid_recomputed=True,
                        post_attempts_this_call=1, post_attempts_total=None, post_response=post,
                        inclusion_verified=False, journal_ok=False, reason='journal_error_reconcile_only')
