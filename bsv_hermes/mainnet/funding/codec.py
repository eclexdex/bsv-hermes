"""Bounded raw-transaction decoding for output binding, not consensus validation."""
from . import MAX_MONEY, _fail, _sha256d
import re


def parse_transaction(text, expected_txid):
    if (type(text) is not str or not 20 <= len(text) <= 200000
            or len(text) % 2 or not re.fullmatch("[0-9a-fA-F]+", text)):
        _fail()
    data = bytes.fromhex(text)
    if _sha256d(data)[::-1].hex() != expected_txid:
        _fail()
    offset = 0

    def take(n):
        nonlocal offset
        if n > len(data) - offset:
            _fail()
        value = data[offset:offset + n]
        offset += n
        return value

    def number(n):
        return int.from_bytes(take(n), "little")

    def compact():
        prefix = number(1)
        if prefix < 253:
            return prefix
        width, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 4294967296)}[prefix]
        value = number(width)
        if value < minimum:
            _fail()
        return value

    def script():
        n = compact()
        if n > 100000:
            _fail("RESOURCE_LIMIT")
        return take(n)

    take(4)
    count = compact()
    if not 1 <= count <= 1000:
        _fail()
    inputs = []
    for _ in range(count):
        previous = take(32)[::-1].hex()
        index = number(4)
        script()
        take(4)
        inputs.append((previous, index))
    count = compact()
    if not 1 <= count <= 1000:
        _fail()
    outputs = []
    for _ in range(count):
        satoshis = number(8)
        if satoshis > MAX_MONEY:
            _fail()
        outputs.append((satoshis, script().hex()))
    take(4)
    if offset != len(data) or sum(x[0] for x in outputs) > MAX_MONEY:
        _fail()
    coinbase = inputs == [("00" * 32, 4294967295)]
    if not coinbase and any(previous == "00" * 32 for previous, _ in inputs):
        _fail()
    if len(set(inputs)) != len(inputs):
        _fail("CONFLICT")
    return {"inputs": inputs, "outputs": outputs, "coinbase": coinbase}
