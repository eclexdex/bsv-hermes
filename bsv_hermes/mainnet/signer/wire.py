"""Bounded independent Bitcoin wire/BIP143-ALL-FORKID verifier primitives.

No SDK calls and no signing here. This deliberately supports only the boundary's
legacy P2PKH transaction subset, not general consensus validation.
"""
import hashlib

MAX_BYTES = 100000
MAX_ITEMS = 1000


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def output_bytes(item):
    script = bytes.fromhex(item['locking_script_hex'])
    return item['satoshis'].to_bytes(8, 'little') + compact(len(script)) + script


def outpoint(item):
    return bytes.fromhex(item['txid'])[::-1] + item['vout'].to_bytes(4, 'little')


def serialize(plan, unlocking_scripts=None):
    scripts = unlocking_scripts or [b''] * len(plan['inputs'])
    raw = plan['version'].to_bytes(4, 'little') + compact(len(plan['inputs']))
    for item, script in zip(plan['inputs'], scripts, strict=True):
        raw += outpoint(item) + compact(len(script)) + script + item['sequence'].to_bytes(4, 'little')
    raw += compact(len(plan['outputs']))
    raw += b''.join(output_bytes(item) for item in plan['outputs'])
    return raw + plan['lock_time'].to_bytes(4, 'little')


def parse(raw):
    if type(raw) is not bytes or not 10 <= len(raw) <= MAX_BYTES:
        raise ValueError('wire')
    offset = 0

    def take(n):
        nonlocal offset
        if n < 0 or offset + n > len(raw):
            raise ValueError('wire')
        result = raw[offset:offset + n]
        offset += n
        return result

    def integer(n):
        return int.from_bytes(take(n), 'little')

    def count(limit):
        flag = integer(1)
        if flag < 253:
            result = flag
        else:
            widths = {253: 2, 254: 4, 255: 8}
            result = integer(widths[flag])
            if result < {253: 253, 254: 65536, 255: 4294967296}[flag]:
                raise ValueError('noncanonical varint')
        if result > limit:
            raise ValueError('wire bounds')
        return result

    version = integer(4)
    inputs = []
    for _ in range(count(MAX_ITEMS)):
        inputs.append({'txid': take(32)[::-1].hex(), 'vout': integer(4),
                       'unlocking_script_hex': take(count(MAX_BYTES)).hex(), 'sequence': integer(4)})
    outputs = []
    for _ in range(count(MAX_ITEMS)):
        outputs.append({'satoshis': integer(8), 'locking_script_hex': take(count(MAX_BYTES)).hex()})
    locktime = integer(4)
    if not inputs or not outputs or offset != len(raw):
        raise ValueError('wire')
    return {'version': version, 'lock_time': locktime, 'inputs': inputs, 'outputs': outputs}


def preimage(plan, index):
    """BSV SIGHASH_ALL | SIGHASH_FORKID (0x41), ForkID=0 only."""
    item = plan['inputs'][index]
    script = bytes.fromhex(item['locking_script_hex'])
    return b''.join((
        plan['version'].to_bytes(4, 'little'),
        hash256(b''.join(outpoint(i) for i in plan['inputs'])),
        hash256(b''.join(i['sequence'].to_bytes(4, 'little') for i in plan['inputs'])),
        outpoint(item), compact(len(script)), script, item['satoshis'].to_bytes(8, 'little'),
        item['sequence'].to_bytes(4, 'little'),
        hash256(b''.join(output_bytes(o) for o in plan['outputs'])),
        plan['lock_time'].to_bytes(4, 'little'), (65).to_bytes(4, 'little'),
    ))


def verify(plan, raw_hex, public_key_hex):
    """Independent SEC1/DER/low-S and OpenSSL ECDSA verification; no network."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    try:
        raw = bytes.fromhex(raw_hex)
        tx = parse(raw)
        if serialize(tx).hex() != plan['unsigned_transaction_hex']:
            return False
        pub_bytes = bytes.fromhex(public_key_hex)
        if len(pub_bytes) != 33 or pub_bytes[0] not in (2, 3):
            return False
        expected_script = '76a914' + hashlib.new('ripemd160', hashlib.sha256(pub_bytes).digest()).hexdigest() + '88ac'
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
        for index, item in enumerate(tx['inputs']):
            if plan['inputs'][index]['locking_script_hex'] != expected_script:
                return False
            script = bytes.fromhex(item['unlocking_script_hex'])
            if not script or not 9 <= script[0] <= 73:
                return False
            length = script[0]
            if len(script) != length + 35 or script[length] != 65 or script[length + 1] != 33:
                return False
            if script[length + 2:] != pub_bytes:
                return False
            signature = script[1:length]
            r, s = utils.decode_dss_signature(signature)
            order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
            if not 1 <= r < order or not 1 <= s <= order // 2:
                return False
            if utils.encode_dss_signature(r, s) != signature:
                return False
            key.verify(signature, hash256(preimage(plan, index)), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False
