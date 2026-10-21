"""Supplied-evidence run receipts. Stdlib, offline, contract v1 adapter.

Never executes a tool, opens caller artifacts, authenticates approval, or signs.
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

FORMAT = 'bsv-hermes.run-receipt-adapter/1'
MAX_BYTES = 1048576
HEX = re.compile(r'^[0-9a-f]{64}$')
ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')


def bounded(value):
    """Bound object graphs before serialization, including cycles/deep nesting."""
    stack = [(value, 0)]
    nodes = 0
    budget = 0
    while stack:
        v, depth = stack.pop()
        nodes += 1
        if nodes > 12000 or depth > 16:
            raise ValueError('budget')
        if type(v) is dict:
            if len(v) > 128 or any(type(k) is not str for k in v):
                raise ValueError('object')
            stack.extend((x, depth+1) for pair in v.items() for x in pair)
        elif type(v) is list:
            if len(v) > 256:
                raise ValueError('array')
            stack.extend((x, depth+1) for x in v)
        elif type(v) is str:
            if len(v) > MAX_BYTES:
                raise ValueError('string')
            budget += len(v.encode('utf-8')) * 6 + 2
        elif v is None or type(v) is bool:
            budget += 5
        elif type(v) is int and abs(v) < 2**53:
            budget += 17
        else:
            raise ValueError('scalar')
        if budget > MAX_BYTES:
            raise ValueError('budget')


def canonical(value):
    bounded(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or set(value)-set(required)-set(optional):
        raise ValueError('fields')


def identifier(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise ValueError('identifier')
    return value


def artifact(value):
    fields(value, ('id',), ('bytes_b64', 'sha256', 'size'))
    if 'size' in value and (type(value['size']) is not int or not 0 <= value['size'] <= 16777216):
        raise ValueError('size')
    identifier(value['id'])
    if 'bytes_b64' not in value and 'sha256' not in value:
        raise ValueError('artifact')
    expected = value.get('sha256')
    if 'sha256' in value and (type(expected) is not str or not HEX.fullmatch(expected)):
        raise ValueError('digest')
    if 'bytes_b64' in value:
        if type(value['bytes_b64']) is not str:
            raise ValueError('bytes')
        raw = base64.b64decode(value['bytes_b64'], validate=True)
        if base64.b64encode(raw).decode('ascii') != value['bytes_b64']:
            raise ValueError('noncanonical base64')
        actual = digest(raw)
        if (expected is not None and expected != actual) or ('size' in value and value['size'] != len(raw)):
            raise ValueError('digest/size mismatch')
        return {'id': value['id'], 'sha256': actual, 'size': len(raw), 'evidence': 'supplied_bytes_hashed'}
    if 'size' not in value:
        raise ValueError('digest-only requires asserted size for contract v1')
    return {'id': value['id'], 'sha256': expected, 'size': value['size'], 'evidence': 'caller_asserted_digest'}


def build_run(request):
    bounded(request)
    fields(request, ('run_id', 'instruction', 'approved_inputs', 'tools', 'final_output'))
    identifier(request['run_id'])
    if type(request['approved_inputs']) is not list or len(request['approved_inputs']) > 128:
        raise ValueError('inputs')
    if type(request['tools']) is not list or len(request['tools']) > 128:
        raise ValueError('tools')
    instruction = artifact(request['instruction'])
    inputs = [artifact(x) for x in request['approved_inputs']]
    output = artifact(request['final_output'])
    ids = [x['id'] for x in [instruction] + inputs + [output]]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate artifact ids')
    def descriptor(a):
        return {'name': a['id'], 'sha256': a['sha256'], 'size': a['size']}
    def h(label, value):
        return digest(('hermes-receipt/v1/' + label + '\x00').encode('ascii') + canonical(value))
    bundle = {'version': 'hermes-receipt/v1', 'instruction': descriptor(instruction),
              'approved_inputs': [descriptor(a) for a in inputs], 'tools': [], 'final_output': descriptor(output)}
    previous = h('start', {k: bundle[k] for k in ('instruction', 'approved_inputs')})
    supplied = [instruction] + inputs + [output]
    tool_ids = set()
    sources = []
    for index, tool in enumerate(request['tools']):
        fields(tool, ('id', 'name', 'arguments', 'result', 'source'))
        identifier(tool['id']); identifier(tool['name'])
        if tool['id'] in tool_ids or tool['source'] not in ('caller_asserted', 'explicit_wrapper_recorded'):
            raise ValueError('tool source/id')
        tool_ids.add(tool['id'])
        args, response = artifact(tool['arguments']), artifact(tool['result'])
        supplied += [args, response]
        event = {'index': index, 'tool': tool['name'], 'request': descriptor(args),
                 'response': descriptor(response), 'previous': previous}
        previous = h('tool', event)
        event['event_digest'] = previous
        bundle['tools'].append(event)
        sources.append({'index': index, 'id': tool['id'], 'source': tool['source'], 'authentication': 'unverified'})
    if len({a['id'] for a in supplied}) != len(supplied):
        raise ValueError('duplicate descriptor names')
    bundle['receipt_digest'] = h('bundle', bundle)
    links = bundle['tools']
    all_bytes = all(a['evidence'] == 'supplied_bytes_hashed' for a in supplied)
    result = {'format': FORMAT + '/result', 'run_id': request['run_id'],
              'receipt_digest': bundle['receipt_digest'],
              'artifact': {'status': 'match' if all_bytes else 'unchecked',
                           'scope': 'supplied bytes only; no retained-file readback',
                           'items': supplied},
              'chain': {'status': 'match', 'scope': 'constructed digest links, not execution truth', 'tool_count': len(links)},
              'signature': {'status': 'missing', 'reason': 'no trusted signature supplied'},
              'batch': {'status': 'missing', 'reason': 'no batch commitment/proof supplied'},
              'inclusion': {'status': 'missing', 'reason': 'no transaction/header/selected-chain evidence supplied'},
              'publication': {'status': 'missing', 'reason': 'no submission performed'},
              'source': {'status': 'unverified', 'approval': 'caller_asserted', 'execution': 'not_authenticated', 'tools': sources,
                         'binding': 'run_id, tool ids and source labels are result metadata, not signed or bound in contract v1'},
              'warning': 'A hash binds supplied evidence; it does not prove execution, completeness, consent or inclusion.'}
    return {'bundle': bundle, 'result': result}


def reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def load_request(path):
    with open(path, 'rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('budget')
    return json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request')
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    try:
        value = build_run(load_request(args.request))
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        # Exclusive writes: never silently replace existing artifacts.
        for name in ('bundle', 'result'):
            with (out / (name + '.json')).open('x', encoding='ascii') as stream:
                stream.write(canonical(value[name]).decode('ascii') + '\n')
        print(json.dumps({'ok': True, 'bundle': str((out/'bundle.json').resolve()), 'result': str((out/'result.json').resolve())}))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, binascii.Error, OSError):
        print(json.dumps({'ok': False, 'error': 'invalid_input_or_output'}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
