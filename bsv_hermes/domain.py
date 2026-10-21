"""Bounded offline data inspection; not a consensus engine."""
import hashlib


def decode_hex(value, maximum):
    if not isinstance(value, str) or len(value) > maximum * 2 or len(value) % 2:
        raise ValueError('hex input type, size or length invalid')
    if any(c not in '0123456789abcdefABCDEF' for c in value):
        raise ValueError('hex input contains non-hex characters')
    return bytes.fromhex(value)


def display_limit(value):
    if type(value) is not int or not 1 <= value <= 100:
        raise ValueError('max_items must be an integer from 1 to 100')
    return value


def inspect_script(script_hex, max_items=20):
    max_items = display_limit(max_items)
    data = decode_hex(script_hex, 10000)
    operations = []
    offset = 0
    count = 0
    while offset < len(data):
        start = offset
        opcode = data[offset]
        offset += 1
        item = {'offset': start, 'opcode': opcode,
                'name': {0: 'OP_FALSE', 106: 'OP_RETURN'}.get(opcode, 'OP_UNKNOWN_%02X' % opcode)}
        size = None
        if 1 <= opcode <= 75:
            size = opcode
        elif opcode in (76, 77, 78):
            width = {76: 1, 77: 2, 78: 4}[opcode]
            if offset + width > len(data):
                raise ValueError('truncated pushdata length')
            size = int.from_bytes(data[offset:offset + width], 'little')
            offset += width
        if size is not None:
            if offset + size > len(data):
                raise ValueError('truncated pushdata payload')
            item.update(name='PUSH', data_hex=data[offset:offset + min(size, 32)].hex(),
                        data_bytes=size, data_truncated=size > 32)
            offset += size
        count += 1
        if len(operations) < max_items:
            operations.append(item)
    return {'size_bytes': len(data), 'operation_count': count, 'operations': operations,
            'truncated': count > len(operations), 'executed': False}


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        if size > len(self.data) - self.offset:
            raise ValueError('truncated transaction field')
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def number(self, width):
        return int.from_bytes(self.take(width), 'little')

    def compact(self):
        marker = self.number(1)
        if marker < 253:
            return marker
        width = {253: 2, 254: 4, 255: 8}[marker]
        value = self.number(width)
        if value < {253: 253, 254: 65536, 255: 4294967296}[marker]:
            raise ValueError('noncanonical CompactSize')
        return value

    def script(self):
        size = self.compact()
        if size > 10000:
            raise ValueError('script exceeds parser policy limit')
        return self.take(size)


def inspect_transaction(transaction_hex, max_items=20):
    max_items = display_limit(max_items)
    data = decode_hex(transaction_hex, 100000)
    reader = Reader(data)
    version = int.from_bytes(reader.take(4), 'little', signed=True)
    input_count = reader.compact()
    if not 1 <= input_count <= 1000:
        raise ValueError('unsupported serialization or input count outside policy')
    inputs = []
    for _ in range(input_count):
        previous = reader.take(32)[::-1].hex()
        index = reader.number(4)
        script = reader.script()
        sequence = reader.number(4)
        inputs.append({'previous_txid': previous, 'output_index': index,
                       'script_bytes': len(script), 'sequence': sequence})
    output_count = reader.compact()
    if not 1 <= output_count <= 1000:
        raise ValueError('output count outside parser policy')
    outputs = []
    for _ in range(output_count):
        amount = reader.number(8)
        script = reader.script()
        outputs.append({'satoshis': amount, 'script_hex': script[:32].hex(),
                        'script_bytes': len(script), 'script_truncated': len(script) > 32})
    locktime = reader.number(4)
    if reader.offset != len(data):
        raise ValueError('trailing bytes or unsupported serialization')
    return {'txid': hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex(),
            'version': version, 'locktime': locktime, 'size_bytes': len(data),
            'input_count': input_count, 'output_count': output_count,
            'inputs': inputs[:max_items], 'outputs': outputs[:max_items],
            'truncated': input_count > max_items or output_count > max_items,
            'fee_satoshis': None, 'consensus_validated': False}


def plan_commitment(text):
    if not isinstance(text, str) or len(text) > 4096:
        raise ValueError('text must be UTF-8 text within 4096 bytes')
    try:
        payload = text.encode('utf-8')
    except UnicodeError:
        raise ValueError('text must be valid UTF-8') from None
    if len(payload) > 4096:
        raise ValueError('text exceeds 4096 UTF-8 bytes')
    digest = hashlib.sha256(payload).hexdigest()
    return {'format': 'sha256-op-return-v1', 'digest_hex': digest,
            'locking_script_hex': '006a20' + digest, 'size_bytes': 35,
            'status': {'signed': False, 'paid': False, 'transaction_built': False, 'broadcast': False}}
