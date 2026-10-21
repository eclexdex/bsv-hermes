"""Offline evidence adapter, stdlib only. No network, wallet or chain oracle."""
import argparse
import hashlib
import json
import re

MAX_BYTES = 2_000_000

def h256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hx(s, size=None):
    if not isinstance(s, str) or len(s) > MAX_BYTES * 2 or len(s) % 2 or re.fullmatch('[0-9a-f]*', s) is None:
        raise ValueError('bounded lowercase hex required')
    b = bytes.fromhex(s)
    if size is not None and len(b) != size:
        raise ValueError('wrong byte length')
    return b

class Reader:
    def __init__(self, b): self.b, self.p = b, 0
    def take(self, n):
        if n < 0 or self.p + n > len(self.b): raise ValueError('truncated transaction')
        v = self.b[self.p:self.p+n]; self.p += n
        return v
    def var(self):
        v = self.take(1)[0]
        if v < 253: return v
        n = {253:2, 254:4, 255:8}[v]
        x = int.from_bytes(self.take(n), 'little')
        if x < {253:253,254:65536,255:4294967296}[v]: raise ValueError('nonminimal compact size')
        return x
    def count(self):
        n = self.var()
        if not 1 <= n <= 10000: raise ValueError('item budget or empty transaction')
        return n

def outputs(raw):
    r = Reader(raw); r.take(4)
    for _ in range(r.count()):
        r.take(36); r.take(r.var()); r.take(4)
    scripts = []
    for _ in range(r.count()):
        r.take(8); scripts.append(r.take(r.var()))
    r.take(4)
    if r.p != len(raw): raise ValueError('trailing bytes or unsupported transaction format')
    return scripts

def pushes(script):
    """Only OP_RETURN/OP_FALSE OP_RETURN followed exclusively by data pushes."""
    if script.startswith(b'\x00\x6a'): script = script[2:]
    elif script.startswith(b'\x6a'): script = script[1:]
    else: return []
    r = Reader(script); result = []
    while r.p < len(script):
        op = r.take(1)[0]
        if op <= 75: n = op
        elif op in (76,77,78): n = int.from_bytes(r.take({76:1,77:2,78:4}[op]), 'little')
        else: raise ValueError('non-data opcode in commitment output')
        result.append(r.take(n))
    return result

def check(status, detail): return {'status':status, 'detail':detail}

def verify(evidence, expected_commitment=None, expected_txid=None):
    """Caller must supply expected bytes/id independently; bundled claims aren't trust."""
    if type(evidence) is not dict: raise ValueError('evidence object required')
    result = {k:check('missing','not supplied') for k in ('publication_plan','submission','provider_report','raw_transaction','txid','commitment','merkle_header','header_pow','selected_chain')}
    for k, field in [('publication_plan','plan'),('submission','submitted'),('provider_report','provider_report')]:
        if field in evidence: result[k] = check('unchecked','unverified source assertion; not proof of publication')
    result['selected_chain'] = check('unchecked','no selected-chain consensus/difficulty/checkpoint validator configured')
    result['spv_verified'] = False
    result['execution_truth'] = check('unchecked','transaction evidence does not authenticate execution')
    if 'raw_tx_hex' not in evidence: return result
    try:
        raw = hx(evidence['raw_tx_hex']); scripts = outputs(raw)
        result['raw_transaction'] = check('match','bounded legacy transaction structure parsed; scripts/prevouts/consensus unchecked')
    except (ValueError, TypeError) as ex:
        result['raw_transaction'] = check('mismatch',str(ex)); return result
    txid = h256(raw)[::-1].hex(); result['computed_txid'] = txid
    if expected_txid is not None:
        result['txid'] = check('match' if hx(expected_txid,32).hex() == txid else 'mismatch','raw bytes double-SHA256 compared with caller expectation')
    else: result['txid'] = check('unchecked','no independent expected txid supplied')
    if expected_commitment is not None:
        commitment = hx(expected_commitment)
        if not commitment: raise ValueError('empty commitment forbidden')
        try:
            found = any(commitment in pushes(s) for s in scripts)
            result['commitment'] = check('match' if found else 'mismatch','exact complete data-push bytes in OP_RETURN output, not substring')
        except ValueError as ex: result['commitment'] = check('mismatch',str(ex))
    if 'header_hex' not in evidence: return result
    try:
        header = hx(evidence['header_hex'],80)
        result['header_hash'] = h256(header)[::-1].hex()
        bits = int.from_bytes(header[72:76], 'little'); exp, mant = bits >> 24, bits & 0x7fffff
        target = (mant << (8*(exp-3))) if exp >= 3 else (mant >> (8*(3-exp)))
        valid_target = not bits & 0x800000 and 0 < target < 2**256
        result['header_pow'] = check('match' if valid_target and int.from_bytes(h256(header),'little') <= target else 'mismatch','self-declared nBits only; network pow limit and required difficulty unchecked')
        if 'merkle_path' in evidence:
            p = evidence['merkle_path']; index = p['index']; sibs = p['siblings']
            if type(index) is not int or index < 0 or type(sibs) is not list or len(sibs)>32 or index >= 2**len(sibs): raise ValueError('path bounds')
            node = h256(raw)
            for sibling in sibs:
                other = hx(sibling,32)[::-1]
                node = h256(other+node if index & 1 else node+other); index >>= 1
            result['merkle_header'] = check('match' if node == header[36:68] else 'mismatch','tx raw hash path matches supplied header only; leaf count, selected chain and confirmations not established')
    except (ValueError,TypeError,KeyError) as ex: result['merkle_header'] = check('mismatch',str(ex))
    return result

def strict_json(text):
    if len(text.encode()) > MAX_BYTES: raise ValueError('JSON byte budget')
    def pairs(items):
        d = {}
        for k,v in items:
            if k in d: raise ValueError('duplicate JSON key')
            d[k] = v
        return d
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence'); p.add_argument('--commitment'); p.add_argument('--txid')
    a = p.parse_args()
    try:
        with open(a.evidence, 'rb') as f: data = f.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise ValueError('file budget')
        r = verify(strict_json(data.decode('utf-8')),a.commitment,a.txid)
        print(json.dumps(r,sort_keys=True,indent=2))
        return 1 if any(isinstance(v,dict) and v.get('status')=='mismatch' for v in r.values()) else 0
    except (ValueError,TypeError,KeyError,RecursionError,OSError) as ex:
        print(json.dumps({'error':str(ex)})); return 2
if __name__ == '__main__': raise SystemExit(main())
