"""Offline independent-v1 adapter. No wallet, Hermes, HTTP or implicit file reads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

MAX_JSON = 1_048_576
MAX_ARTIFACT = 16_777_216
MAX_ITEMS = 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")

class Invalid(ValueError):
    pass

def digest(data):
    return hashlib.sha256(data).hexdigest()

def double(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def strict_load(data):
    if len(data) > MAX_JSON:
        raise Invalid('JSON byte budget exceeded')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Invalid('duplicate JSON key')
            out[key] = value
        return out
    def reject(value):
        raise Invalid('floats and nonfinite numbers forbidden')
    def integer(value):
        if len(value.lstrip('-')) > 16:
            raise Invalid('integer digit budget exceeded')
        number = int(value)
        if abs(number) > 9007199254740991:
            raise Invalid('unsafe JSON integer')
        return number
    try:
        obj = json.loads(data, object_pairs_hook=pairs, parse_int=integer, parse_float=reject, parse_constant=reject)
        count = [0]
        def walk(v, depth=0):
            count[0] += 1
            if depth > 24 or count[0] > 20000:
                raise Invalid('JSON structure budget exceeded')
            if isinstance(v, dict):
                if len(v) > MAX_ITEMS:
                    raise Invalid('object budget exceeded')
                for k, x in v.items():
                    k.encode('utf-8')
                    walk(x, depth + 1)
            elif isinstance(v, list):
                if len(v) > MAX_ITEMS:
                    raise Invalid('array budget exceeded')
                for x in v:
                    walk(x, depth + 1)
            elif isinstance(v, str):
                v.encode('utf-8')
            elif v is not None and type(v) not in (bool, int):
                raise Invalid('unsupported JSON value')
        walk(obj)
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid(str(exc)) from exc

def fields(obj, required, optional=()):
    if not isinstance(obj, dict) or set(obj) - set(required) - set(optional) or set(required) - set(obj):
        raise Invalid('wrong object fields; required=' + ','.join(required))

def h(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise Invalid('expected lowercase SHA256 hex')
    return value

def text(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise Invalid('invalid identifier')
    return value

def uint(value, maximum=MAX_ITEMS):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Invalid('expected bounded integer, not bool')
    return value

def hexbytes(value, maximum=MAX_JSON):
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2 or not re.fullmatch('[0-9a-f]*', value):
        raise Invalid('invalid bounded lowercase hex')
    return bytes.fromhex(value)

def read_regular(path, limit):
    # Reject symlink components; open exact caller-approved file, not a bundle path.
    if '..' in Path(path).parts:
        raise Invalid('traversal in explicit file grant')
    path = Path(os.path.abspath(os.fspath(path)))
    # Descriptor-relative walk prevents parent-directory symlink substitution races.
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Invalid('not a regular file or file budget exceeded')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Invalid('file budget exceeded')
    return data

def result(status, detail, **extra):
    return dict(status=status, detail=detail, **extra)

def check_bundle(bundle):
    fields(bundle, ('format', 'instruction_sha256', 'artifacts', 'events', 'chain_head'), ('signature', 'batch', 'inclusion', 'provider_report'))
    if bundle['format'] != 'independent-v1':
        raise Invalid('unsupported format; explicit contract adapter required')
    h(bundle['instruction_sha256']); h(bundle['chain_head'])
    if not isinstance(bundle['artifacts'], list) or len(bundle['artifacts']) > MAX_ITEMS:
        raise Invalid('artifact budget')
    seen = set()
    for item in bundle['artifacts']:
        fields(item, ('id', 'role', 'sha256', 'size'))
        text(item['id']); h(item['sha256']); uint(item['size'], MAX_ARTIFACT)
        if item['role'] not in ('input', 'output') or item['id'] in seen:
            raise Invalid('invalid role or duplicate artifact id')
        seen.add(item['id'])
    if not isinstance(bundle['events'], list) or len(bundle['events']) > MAX_ITEMS:
        raise Invalid('event budget')
    for i, event in enumerate(bundle['events']):
        fields(event, ('index', 'kind', 'payload_sha256', 'previous', 'hash'))
        uint(event['index']); text(event['kind']); h(event['payload_sha256']); h(event['previous']); h(event['hash'])
        if event['index'] != i:
            raise Invalid('noncontiguous event indices')

def core(bundle):
    return {k: bundle[k] for k in ('format', 'instruction_sha256', 'artifacts', 'events', 'chain_head')}

def receipt_hash(bundle):
    if '_contract_digest' in bundle:
        return bundle['_contract_digest']
    return digest(b'hermes-independent-receipt-v1\x00' + canonical(core(bundle)))

def chain_check(bundle):
    genesis = {k: bundle[k] for k in ('format', 'instruction_sha256', 'artifacts')}
    previous = digest(b'hermes-independent-chain-v1\x00' + canonical(genesis))
    for event in bundle['events']:
        body = {k: event[k] for k in ('index', 'kind', 'payload_sha256', 'previous')}
        calculated = digest(b'hermes-independent-event-v1\x00' + canonical(body))
        if event['previous'] != previous or event['hash'] != calculated:
            return result('mismatch', 'event hash or predecessor mismatch; source remains unverified')
        previous = calculated
    return result('match' if previous == bundle['chain_head'] else 'mismatch', 'hash linkage only; execution and event source unverified')

def signature_check(bundle, trusted_key):
    sidecar = bundle.get('signature')
    if sidecar is None:
        return result('missing', 'no signature')
    if trusted_key is None:
        return result('unchecked', 'caller did not supply trusted public key; bundled keys never trusted')
    try:
        fields(sidecar, ('algorithm', 'value'))
        if sidecar['algorithm'] != 'Ed25519':
            raise Invalid('unsupported signature algorithm')
        key = hexbytes(trusted_key, 32); sig = hexbytes(sidecar['value'], 64)
        if len(key) != 32 or len(sig) != 64:
            raise Invalid('invalid Ed25519 lengths')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return result('unchecked', 'Ed25519 dependency unavailable; not verified', available=False)
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, b'hermes-independent-signature-v1\x00' + bytes.fromhex(receipt_hash(bundle)))
        except (InvalidSignature, ValueError):
            return result('mismatch', 'signature rejected by caller-trusted key')
        return result('match', 'signature binds receipt core, not execution truth, approval, expiry or inclusion', key_sha256=digest(key), available=True)
    except Invalid as exc:
        return result('mismatch', str(exc))

def batch_check(bundle, trusted_root):
    proof = bundle.get('batch')
    if proof is None:
        return result('missing', 'no batch proof')
    if trusted_root is None:
        return result('unchecked', 'caller did not specify batch commitment')
    try:
        h(trusted_root); fields(proof, ('leaf_index', 'leaf_count', 'siblings'))
        index = uint(proof['leaf_index']); count = uint(proof['leaf_count'])
        if count == 0 or index >= count or not isinstance(proof['siblings'], list) or len(proof['siblings']) > 10:
            raise Invalid('invalid batch geometry')
        node = hashlib.sha256(b'\x00' + bytes.fromhex(receipt_hash(bundle))).digest()
        siblings = iter(proof['siblings'])
        while count > 1:
            sibling = bytes.fromhex(h(next(siblings)))
            # Odd terminal leaves are duplicated, never arbitrary supplied siblings.
            if index % 2 == 0 and index + 1 == count and sibling != node:
                raise Invalid('odd leaf must duplicate itself')
            node = hashlib.sha256(b'\x01' + (sibling + node if index % 2 else node + sibling)).digest()
            index //= 2; count = (count + 1) // 2
        if next(siblings, None) is not None:
            raise Invalid('extra batch sibling')
        return result('match' if node.hex() == trusted_root else 'mismatch', 'receipt leaf proof against caller-specified root only')
    except (Invalid, StopIteration) as exc:
        return result('mismatch', str(exc) or 'missing batch sibling')

class TxReader:
    def __init__(self, raw):
        self.raw, self.pos = raw, 0
    def take(self, n):
        if n < 0 or self.pos + n > len(self.raw):
            raise Invalid('truncated transaction')
        out = self.raw[self.pos:self.pos+n]; self.pos += n
        return out
    def varint(self):
        prefix = self.take(1)[0]
        n = prefix if prefix < 253 else int.from_bytes(self.take({253:2,254:4,255:8}[prefix]), 'little')
        if prefix >= 253 and n < {253:253,254:65536,255:4294967296}[prefix]:
            raise Invalid('noncanonical varint')
        return uint(n, MAX_JSON)

def output_scripts(raw):
    r = TxReader(raw); r.take(4)
    count = r.varint()
    if not 1 <= count <= MAX_ITEMS:
        raise Invalid('input count outside bounds / segwit unsupported')
    for _ in range(count):
        r.take(36); r.take(r.varint()); r.take(4)
    count = r.varint()
    if not 1 <= count <= MAX_ITEMS:
        raise Invalid('output count outside bounds')
    scripts = []
    for _ in range(count):
        r.take(8); scripts.append(r.take(r.varint()))
    r.take(4)
    if r.pos != len(raw):
        raise Invalid('trailing transaction bytes')
    return scripts

def inclusion_checks(bundle, trusted_header, commitment):
    absent = result('missing', 'no offline inclusion evidence')
    out = {'transaction_commitment': absent, 'merkle_inclusion': absent,
           'header_anchor': result('unchecked', 'no caller-selected header hash'),
           'selected_chain': result('unchecked', 'no header chain or cumulative-work validation implemented'),
           'provider_report': result('unchecked' if 'provider_report' in bundle else 'missing', 'provider assertion is not independent inclusion evidence')}
    evidence = bundle.get('inclusion')
    if evidence is None:
        return out
    try:
        fields(evidence, ('rawtx', 'txid', 'header', 'index', 'siblings'))
        raw = hexbytes(evidence['rawtx']); header = hexbytes(evidence['header'], 80)
        if len(header) != 80:
            raise Invalid('header must be 80 bytes')
        txid = double(raw)[::-1].hex(); h(evidence['txid'])
        scripts = output_scripts(raw)
        if txid != evidence['txid']:
            raise Invalid('raw transaction txid mismatch')
        if commitment is None:
            out['transaction_commitment'] = result('unchecked', 'caller did not specify exact commitment bytes')
        else:
            payload = hexbytes(commitment, 75)
            if not payload:
                raise Invalid('empty commitment forbidden')
            wanted = bytes([0x6a, len(payload)]) + payload
            wanted_false = b'\x00' + wanted
            out['transaction_commitment'] = result('match' if any(s in (wanted, wanted_false) for s in scripts) else 'mismatch', 'exact standalone OP_RETURN push; no substring matching')
        index = uint(evidence['index'], 2**32 - 1)
        if not isinstance(evidence['siblings'], list) or len(evidence['siblings']) > 32:
            raise Invalid('merkle proof budget')
        node = double(raw)
        for sibling in evidence['siblings']:
            other = bytes.fromhex(h(sibling))[::-1]
            if other == node:
                raise Invalid('ambiguous duplicated merkle branch rejected conservatively')
            node = double(other + node if index & 1 else node + other)
            index >>= 1
        if index:
            raise Invalid('index exceeds merkle depth')
        out['merkle_inclusion'] = result('match' if node == header[36:68] else 'mismatch', 'transaction Merkle path against supplied header; header may be synthetic or untrusted')
        if trusted_header is not None:
            h(trusted_header)
            out['header_anchor'] = result('match' if double(header)[::-1].hex() == trusted_header else 'mismatch', 'header hash against caller-selected anchor; no network or chain validation')
    except Invalid as exc:
        out['merkle_inclusion'] = result('mismatch', str(exc))
        if out['transaction_commitment']['status'] == 'missing':
            out['transaction_commitment'] = result('mismatch', str(exc))
    return out

def contract_canonical(value):
    def walk(v):
        if type(v) is int and abs(v) > 9007199254740991:
            raise Invalid('unsafe contract integer')
        if isinstance(v, dict):
            for k, x in v.items():
                if not k.isascii():
                    raise Invalid('non-ASCII contract key')
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def contract_h(label, value):
    return digest(('hermes-receipt/v1/' + label).encode('ascii') + b'\x00' + contract_canonical(value))

def verify_contract(bundle, grants, trusted_key, batch_root, trusted_header, commitment):
    """Independent implementation of sibling CONTRACT.md; no sibling imports."""
    sidecars = {}
    if bundle.get('adapter') == 'hermes-receipt/v1-external-v1':
        fields(bundle, ('adapter', 'bundle'), ('signature', 'batch', 'inclusion', 'provider_report'))
        sidecars = {k: v for k, v in bundle.items() if k not in ('adapter', 'bundle')}
        bundle = bundle['bundle']
    fields(bundle, ('version', 'instruction', 'approved_inputs', 'tools', 'final_output', 'receipt_digest'))
    if bundle['version'] != 'hermes-receipt/v1':
        raise Invalid('unsupported receipt contract')
    contract_canonical(bundle)
    h(bundle['receipt_digest'])
    names = set(); artifacts = []
    def descriptor(item, role):
        fields(item, ('name', 'sha256', 'size'))
        text(item['name']); h(item['sha256']); uint(item['size'], MAX_ARTIFACT)
        if item['name'] in names:
            raise Invalid('duplicate descriptor name')
        names.add(item['name'])
        artifacts.append(dict(id=item['name'], role=role, sha256=item['sha256'], size=item['size']))
    descriptor(bundle['instruction'], 'instruction')
    if not isinstance(bundle['approved_inputs'], list) or not isinstance(bundle['tools'], list):
        raise Invalid('contract arrays required')
    for item in bundle['approved_inputs']:
        descriptor(item, 'input')
    previous = contract_h('start', {k: bundle[k] for k in ('instruction', 'approved_inputs')})
    linked = True
    for index, event in enumerate(bundle['tools']):
        fields(event, ('index', 'tool', 'request', 'response', 'previous', 'event_digest'))
        uint(event['index']); text(event['tool']); h(event['previous']); h(event['event_digest'])
        descriptor(event['request'], 'tool_request'); descriptor(event['response'], 'tool_response')
        expected = contract_h('tool', {k: v for k, v in event.items() if k != 'event_digest'})
        linked = linked and event['index'] == index and event['previous'] == previous and event['event_digest'] == expected
        previous = event['event_digest']
    descriptor(bundle['final_output'], 'output')
    calculated = contract_h('bundle', {k: v for k, v in bundle.items() if k != 'receipt_digest'})
    linked = linked and calculated == bundle['receipt_digest']
    # Internal neutral shape is not serialized or accepted as an input format.
    normalized = dict(format='independent-v1', instruction_sha256=bundle['instruction']['sha256'],
                      artifacts=[dict(x, role='output' if x['role'] == 'output' else 'input') for x in artifacts],
                      events=[], chain_head='0'*64, **sidecars)
    report = verify(normalized, grants, trusted_key=None, batch_root=None, trusted_header=trusted_header, commitment=commitment)
    for check, artifact in zip(report['artifact_bytes'], artifacts):
        check['role'] = artifact['role']
    # Recompute core digest: never verify signatures or proofs against a merely asserted receipt_digest.
    normalized['_contract_digest'] = calculated
    report['adapter'] = 'hermes-receipt/v1-external-v1'
    report['receipt_digest'] = calculated
    report['evidence_chain'] = result('match' if linked else 'mismatch', 'contract digest and ordered hash linkage only; event source and execution unverified')
    report['signature'] = signature_check(normalized, trusted_key)
    report['batch'] = batch_check(normalized, batch_root)
    return report

def verify(bundle, approved_artifacts=None, trusted_key=None, batch_root=None, trusted_header=None, commitment=None):
    # Library callers receive the same validation/budgets as CLI callers.
    try:
        bounded_object(bundle)
        bundle = strict_load(canonical(bundle))
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise Invalid(str(exc)) from exc
    if not isinstance(bundle, dict):
        raise Invalid('bundle must be an object')
    if 'version' in bundle or 'adapter' in bundle:
        return verify_contract(bundle, approved_artifacts or {}, trusted_key, batch_root, trusted_header, commitment)
    check_bundle(bundle)
    grants = approved_artifacts or {}
    if not isinstance(grants, dict) or set(grants) - {x['id'] for x in bundle['artifacts']}:
        raise Invalid('unknown artifact grant')
    artifacts = []
    for artifact in bundle['artifacts']:
        if artifact['id'] not in grants:
            check = result('unchecked', 'no explicit caller-approved file path')
        else:
            try:
                data = read_regular(grants[artifact['id']], MAX_ARTIFACT)
                check = result('match' if len(data) == artifact['size'] and digest(data) == artifact['sha256'] else 'mismatch', 'approved file bytes only; not execution truth')
            except FileNotFoundError:
                check = result('missing', 'approved file does not exist')
            except (OSError, Invalid) as exc:
                check = result('mismatch', str(exc))
        artifacts.append(dict(id=artifact['id'], role=artifact['role'], **check))
    return {'report_format': 'independent-verifier-report-v1', 'adapter': 'independent-v1',
            'artifact_bytes': artifacts, 'evidence_chain': chain_check(bundle),
            'signature': signature_check(bundle, trusted_key), 'batch': batch_check(bundle, batch_root),
            'inclusion': inclusion_checks(bundle, trusted_header, commitment),
            'source_authentication': result('unchecked', 'event source and execution not independently witnessed; receipt hashes or signatures do not establish execution truth')}

def bounded_object(value):
    """Reject oversized/cyclic native objects before allocating serialized JSON."""
    stack = [(value, 0)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 24 or nodes > 20000:
            raise Invalid('JSON structure budget exceeded')
        if type(item) is dict:
            if len(item) > MAX_ITEMS or any(type(k) is not str for k in item):
                raise Invalid('object budget or key type')
            size += 2 + 2 * len(item)
            stack.extend((v, depth+1) for pair in item.items() for v in pair)
        elif type(item) is list:
            if len(item) > MAX_ITEMS:
                raise Invalid('array budget exceeded')
            size += 2 + len(item)
            stack.extend((v, depth+1) for v in item)
        elif type(item) is str:
            if len(item) > MAX_JSON:
                raise Invalid('string budget exceeded')
            # Conservative escaped-JSON ceiling, including supplementary Unicode.
            size += 2 + sum(12 if ord(c) > 65535 else 6 for c in item)
            item.encode('utf-8')
        elif item is None or type(item) is bool:
            size += 5
        elif type(item) is int and abs(item) <= 9007199254740991:
            size += 17
        else:
            raise Invalid('unsupported JSON scalar')
        if size > MAX_JSON:
            raise Invalid('JSON byte budget exceeded')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle')
    parser.add_argument('--artifact', action='append', default=[], metavar='ID=APPROVED_PATH')
    parser.add_argument('--trusted-key', help='caller-trusted Ed25519 public key, lowercase hex')
    parser.add_argument('--batch-root', help='caller-specified batch root, lowercase hex')
    parser.add_argument('--trusted-header', help='caller-selected Bitcoin header hash, display order')
    parser.add_argument('--commitment', help='exact expected OP_RETURN payload, lowercase hex (1..75 bytes)')
    args = parser.parse_args(argv)
    try:
        grants = {}
        for grant in args.artifact:
            key, sep, path = grant.partition('=')
            if not sep or not path or key in grants:
                raise Invalid('invalid or duplicate artifact grant')
            grants[key] = path
        report = verify(strict_load(read_regular(args.bundle, MAX_JSON)), grants, args.trusted_key, args.batch_root, args.trusted_header, args.commitment)
        print(json.dumps(report, sort_keys=True, indent=2))
        # This exit code is transport completion, NEVER an overall verification badge.
        return 0
    except (Invalid, OSError, TypeError, OverflowError) as exc:
        print(json.dumps({'error': str(exc), 'report_format': 'independent-verifier-error-v1'}))
        return 2

if __name__ == '__main__':
    sys.exit(main())
