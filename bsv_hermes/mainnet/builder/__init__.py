"""Offline BSV P2PKH unsigned construction. No signing or network code."""
import hashlib
import json
import re

MAX_MONEY = 2100000000000000
MAX_TRANSACTION_BYTES = 100000
MAX_INPUTS = 1000
MAX_OUTPUTS = 1000
MAX_DATA_BYTES = 8192
MAX_REQUEST_BYTES = 1048576
# Conservative P2PKH scriptSig bound: push(73-byte DER+sighash) plus
# push(33-byte compressed public key). No signature generation here.
MAX_UNLOCKING_SCRIPT_BYTES = 108


def handle_request(request):
    """Shared ok/result/error envelope for an already-decoded request."""
    try:
        return {'ok': True, 'result': build_unsigned(request)}
    except BuilderError as error:
        return {'ok': False, 'error': {'code': error.code, 'message': str(error)}}


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _invalid('Duplicate JSON object key.')
        value[key] = item
    return value


def _json_integer(value):
    if len(value) > 16:
        _invalid('JSON integer is too large.')
    return int(value)


def _json_noninteger(value):
    _invalid('JSON numbers must be bounded integer literals.')


def build_json(text):
    """Strict bounded JSON to JSON-string envelope; no file/network access."""
    try:
        if type(text) is not str:
            _invalid('Request must be UTF-8 JSON text.')
        if len(text) > MAX_REQUEST_BYTES or len(text.encode('utf-8')) > MAX_REQUEST_BYTES:
            raise BuilderError('request_limit', 'JSON request exceeds the byte cap.')
        request = json.loads(text, object_pairs_hook=_json_object, parse_int=_json_integer,
                             parse_float=_json_noninteger, parse_constant=_json_noninteger)
        response = handle_request(request)
    except BuilderError as error:
        response = {'ok': False, 'error': {'code': error.code, 'message': str(error)}}
    except (ValueError, UnicodeError, RecursionError):
        response = {'ok': False, 'error': {'code': 'invalid_input', 'message': 'Malformed or overly nested JSON request.'}}
    return json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


class BuilderError(ValueError):
    """Stable, non-secret error suitable for the integration envelope."""
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _invalid(message):
    raise BuilderError('invalid_input', message)


def _object(value, required, optional=()):
    if type(value) is not dict or len(value) > len(required) + len(optional):
        _invalid('Expected an object with only documented fields.')
    if any(type(key) is not str for key in value):
        _invalid('Object keys must be strings.')
    if not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        _invalid('Missing or unknown field.')


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        _invalid(label + ' must be an integer within the documented range.')


def _hex(value, size, exact=False):
    if (type(value) is not str or len(value) > 2 * size or len(value) % 2
            or (exact and len(value) != 2 * size)
            or re.fullmatch('[0-9a-f]*', value) is None):
        _invalid('Hex must be bounded, even-length, lowercase, and whitespace-free.')


def _p2pkh(value):
    _hex(value, 25, exact=True)
    if not value.startswith('76a914') or not value.endswith('88ac'):
        _invalid('Only canonical 25-byte P2PKH locking scripts are supported.')


def _address_script(address, network):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if type(address) is not str or not 26 <= len(address) <= 35:
        _invalid('P2PKH address must be a 26 to 35 character Base58Check string.')
    value = 0
    for character in address:
        digit = alphabet.find(character)
        if digit < 0:
            _invalid('Address contains a non-Base58 character.')
        value = value * 58 + digit
    raw = b'\x00' * (len(address) - len(address.lstrip('1')))
    raw += value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if len(raw) != 25:
        _invalid('Address payload length is invalid.')
    if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        _invalid('Address checksum is invalid.')
    if raw[0] != (0 if network == 'mainnet' else 111):
        _invalid('Address is not P2PKH for the explicit network.')
    return '76a914' + raw[1:21].hex() + '88ac'


def _destination(item, network, recipient=False):
    _object(item, ('satoshis',) if recipient else (), ('address', 'locking_script_hex'))
    if ('address' in item) == ('locking_script_hex' in item):
        _invalid('Supply exactly one destination address or locking_script_hex.')
    if 'address' in item:
        return _address_script(item['address'], network)
    _p2pkh(item['locking_script_hex'])
    return item['locking_script_hex']


def _validate(request):
    _object(request, ('schema', 'network', 'operation', 'utxos', 'outputs', 'change', 'fee_policy'), ('data_hex_chunks',))
    if request['schema'] != 'bsv-unsigned-build-request-v1':
        _invalid('Unsupported request schema.')
    if request['network'] not in ('mainnet', 'testnet'):
        _invalid('Explicit BSV mainnet or testnet is required.')
    if request['operation'] not in ('funding', 'payment', 'publication'):
        _invalid('Unsupported operation.')
    publication = request['operation'] == 'publication'
    if publication:
        chunks = request.get('data_hex_chunks')
        if type(chunks) is not list or not 1 <= len(chunks) <= 128:
            _invalid('Publication requires 1 to 128 hexadecimal data chunks.')
        for chunk in chunks:
            _hex(chunk, MAX_DATA_BYTES)
        if sum(len(chunk) // 2 for chunk in chunks) > MAX_DATA_BYTES:
            _invalid('Total publication payload exceeds 8192 bytes.')
    elif 'data_hex_chunks' in request:
        _invalid('Data chunks are only accepted for publication.')
    policy = request['fee_policy']
    _object(policy, ('satoshis_per_kilobyte', 'dust_threshold_satoshis', 'dust_change',
                     'max_fee_satoshis', 'max_transaction_bytes'))
    _integer(policy['satoshis_per_kilobyte'], 1, 100000000, 'Fee rate')
    _integer(policy['dust_threshold_satoshis'], 1, MAX_MONEY, 'Dust threshold')
    _integer(policy['max_fee_satoshis'], 0, MAX_MONEY, 'Maximum fee')
    _integer(policy['max_transaction_bytes'], 1, MAX_TRANSACTION_BYTES, 'Size cap')
    if policy['dust_change'] not in ('add_to_fee', 'reject'):
        _invalid('Dust change policy must be add_to_fee or reject.')
    inputs = request['utxos']
    outputs = request['outputs']
    if type(inputs) is not list or not 1 <= len(inputs) <= MAX_INPUTS:
        _invalid('Supply between 1 and 1000 UTXOs.')
    if type(outputs) is not list or not (0 if publication else 1) <= len(outputs) <= MAX_OUTPUTS - 1 - int(publication):
        _invalid('Recipient count exceeds bounds; funding/payment require a recipient.')
    seen = set()
    for item in inputs:
        _object(item, ('txid', 'vout', 'satoshis', 'locking_script_hex', 'unlocking_template'))
        _hex(item['txid'], 32, exact=True)
        _integer(item['vout'], 0, 0xffffffff, 'UTXO vout')
        _integer(item['satoshis'], 1, MAX_MONEY, 'UTXO satoshis')
        _p2pkh(item['locking_script_hex'])
        if item['unlocking_template'] != 'p2pkh-compressed':
            _invalid('Only p2pkh-compressed unlocking is supported.')
        outpoint = (item['txid'], item['vout'])
        if outpoint in seen or outpoint == ('00' * 32, 0xffffffff):
            _invalid('Duplicate or null outpoint.')
        seen.add(outpoint)
    for item in outputs:
        _destination(item, request['network'], recipient=True)
        _integer(item['satoshis'], policy['dust_threshold_satoshis'], MAX_MONEY, 'Output satoshis')
    _destination(request['change'], request['network'])
    if sum(item['satoshis'] for item in inputs) > MAX_MONEY or sum(item['satoshis'] for item in outputs) > MAX_MONEY:
        _invalid('Aggregate amounts exceed the monetary bound.')


def _op_return(chunks):
    script = bytearray(b'\x00\x6a')
    for chunk in chunks:
        data = bytes.fromhex(chunk)
        size = len(data)
        if size <= 75:
            script.append(size)
        elif size <= 255:
            script.extend(bytes([0x4c, size]))
        else:
            script.extend(b'\x4d' + size.to_bytes(2, 'little'))
        script.extend(data)
    return script.hex()


def _compact(value):
    # Every caller value is bounded by the request policy below 65536.
    if value < 253:
        return bytes([value])
    return b'\xfd' + value.to_bytes(2, 'little')


def _serialize(inputs, outputs):
    raw = bytearray(b'\x01\x00\x00\x00' + _compact(len(inputs)))
    for item in inputs:
        raw.extend(bytes.fromhex(item['txid'])[::-1])
        raw.extend(item['vout'].to_bytes(4, 'little'))
        raw.extend(b'\x00\xff\xff\xff\xff')
    raw.extend(_compact(len(outputs)))
    for item in outputs:
        script = bytes.fromhex(item['locking_script_hex'])
        raw.extend(item['satoshis'].to_bytes(8, 'little'))
        raw.extend(_compact(len(script)))
        raw.extend(script)
    raw.extend(b'\x00\x00\x00\x00')
    return bytes(raw)


def build_unsigned(request):
    """Consume all explicitly supplied UTXOs, preserving input/recipient order.

    The returned empty-scriptSig transaction is not ready for broadcast. Its
    txid changes on signing; the intent ID is a content digest, not approval.
    """
    _validate(request)
    canonical = json.dumps(request, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    request = json.loads(canonical)  # No aliases into caller-owned containers.
    inputs = request['utxos']
    outputs = [{'satoshis': item['satoshis'], 'locking_script_hex': _destination(item, request['network'], True),
                'role': 'recipient'} for item in request['outputs']]
    if request['operation'] == 'publication':
        outputs.append({'satoshis': 0, 'locking_script_hex': _op_return(request['data_hex_chunks']), 'role': 'data'})
    change = {'locking_script_hex': _destination(request['change'], request['network']), 'satoshis': 0, 'role': 'change'}
    total = sum(item['satoshis'] for item in inputs)
    amount = sum(item['satoshis'] for item in outputs)
    policy = request['fee_policy']
    no_change = _serialize(inputs, outputs)
    no_change_size = len(no_change) + MAX_UNLOCKING_SCRIPT_BYTES * len(inputs)
    no_change_fee = (no_change_size * policy['satoshis_per_kilobyte'] + 999) // 1000
    available = total - amount
    if available < no_change_fee:
        raise BuilderError('insufficient_funds', 'Supplied UTXOs do not cover outputs and the minimum fee.')
    projected = _serialize(inputs, outputs + [change])
    with_change_size = len(projected) + MAX_UNLOCKING_SCRIPT_BYTES * len(inputs)
    with_change_fee = (with_change_size * policy['satoshis_per_kilobyte'] + 999) // 1000
    candidate_change = available - with_change_fee
    if candidate_change >= policy['dust_threshold_satoshis']:
        change['satoshis'] = candidate_change
        outputs.append(change)
        maximum_size = with_change_size
        fee = minimum_fee = with_change_fee
    else:
        maximum_size = no_change_size
        minimum_fee = no_change_fee
        fee = available
        if fee > minimum_fee and policy['dust_change'] == 'reject':
            raise BuilderError('dust_change', 'Uneconomic change would increase the fee; explicit add_to_fee policy required.')
    if fee > policy['max_fee_satoshis']:
        raise BuilderError('fee_limit', 'Transaction fee exceeds the explicit maximum.')
    if maximum_size > policy['max_transaction_bytes']:
        raise BuilderError('size_limit', 'Maximum signed size exceeds the explicit byte cap.')
    raw = _serialize(inputs, outputs)
    return {
        'schema': 'bsv-unsigned-build-result-v1',
        'chain': 'bsv',
        'network': request['network'],
        'operation': request['operation'],
        'intent_id': hashlib.sha256(b'bsv-unsigned-build-v1\x00' + canonical.encode('ascii')).hexdigest(),
        'request': request,
        'version': 1,
        'locktime': 0,
        'input_satoshis': total,
        'output_satoshis': sum(item['satoshis'] for item in outputs),
        'signing_inputs': [dict(item, input_index=index, sequence=0xffffffff) for index, item in enumerate(inputs)],
        'signing_requirements': {
            'template': 'p2pkh-compressed',
            'sighash_type': 65,
            'maximum_unlocking_script_bytes': MAX_UNLOCKING_SCRIPT_BYTES,
            'public_key_bytes': 33,
        },
        'validation': {'utxos_verified': False, 'consensus_validated': False, 'fee_quote_verified': False},
        'outputs': [dict(item, output_index=index) for index, item in enumerate(outputs)],
        'unsigned_transaction_hex': raw.hex(),
        'unsigned_txid': hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(),
        'unsigned_size_bytes': len(raw),
        'maximum_signed_size_bytes': maximum_size,
        'fee_satoshis': fee,
        'minimum_fee_satoshis': minimum_fee,
        'excess_fee_satoshis': fee - minimum_fee,
        'change_satoshis': change['satoshis'],
        'status': {'transaction_built': True, 'signed': False, 'broadcast': False},
    }
