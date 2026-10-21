"""Strict bounded legacy transaction inspection, NOT signature validation."""
import hashlib
import re
from .errors import PublishError

MAX_MONEY = 2100000000000000


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise PublishError('invalid_integer')
    return value


def hex_bytes(value, maximum, minimum=0):
    if type(value) is not str or not minimum * 2 <= len(value) <= maximum * 2 or len(value) % 2 or re.fullmatch('[0-9a-f]*', value) is None:
        raise PublishError('invalid_hex')
    return bytes.fromhex(value)


class Reader:
    def __init__(self, raw):
        self.raw, self.pos = raw, 0

    def take(self, count):
        if self.pos + count > len(self.raw):
            raise PublishError('invalid_transaction')
        start = self.pos
        self.pos += count
        return self.raw[start:self.pos]

    def number(self, count):
        return int.from_bytes(self.take(count), 'little')

    def compact(self):
        marker = self.number(1)
        if marker < 253:
            return marker
        value = self.number({253: 2, 254: 4, 255: 8}[marker])
        if value < {253: 253, 254: 65536, 255: 4294967296}[marker]:
            raise PublishError('invalid_transaction')
        return value

    def script(self):
        count = self.compact()
        if count > 10000:
            raise PublishError('invalid_transaction')
        return self.take(count).hex()


def parse(raw_hex):
    raw = hex_bytes(raw_hex, 100000, 10)
    r = Reader(raw)
    version = r.number(4)
    count = integer(r.compact(), 1, 50)
    inputs = []
    for _ in range(count):
        inputs.append({'txid': r.take(32)[::-1].hex(), 'vout': r.number(4),
                       'script_hex': r.script(), 'sequence': r.number(4)})
    count = integer(r.compact(), 1, 2)
    outputs = []
    for _ in range(count):
        outputs.append({'satoshis': integer(r.number(8), 0, MAX_MONEY), 'script_hex': r.script()})
    locktime = r.number(4)
    if r.pos != len(raw):
        raise PublishError('invalid_transaction')
    return {'version': version, 'inputs': inputs, 'outputs': outputs, 'locktime': locktime,
            'txid': hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()}


def skeleton(transaction):
    return {'version': transaction['version'], 'locktime': transaction['locktime'],
            'outputs': transaction['outputs'],
            'inputs': [{k: v for k, v in item.items() if k != 'script_hex'} for item in transaction['inputs']]}
