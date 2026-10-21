"""Standalone hermes-receipt/v1 builder and strict integrity verifier."""
import hashlib
import json
import re
import sys

VERSION = 'hermes-receipt/v1'
MAX = 9007199254740991


def canonical(value):
    def check(x):
        if x is None or type(x) is bool:
            return
        if type(x) is int and abs(x) <= MAX:
            return
        if type(x) is str and not any(0xD800 <= ord(c) <= 0xDFFF for c in x):
            return
        if type(x) is list:
            for v in x:
                check(v)
            return
        if type(x) is dict:
            for k, v in x.items():
                if type(k) is not str or not k.isascii():
                    raise ValueError('non-ASCII object key')
                check(v)
            return
        raise ValueError('unsupported canonical value')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def preimage(label, value):
    if label not in ('start', 'tool', 'bundle'):
        raise ValueError('unknown domain')
    return (VERSION + '/' + label).encode('ascii') + b'\0' + canonical(value)


def digest(label, value):
    return hashlib.sha256(preimage(label, value)).hexdigest()


def descriptor(name, data):
    if type(data) is not bytes:
        raise ValueError('content must be bytes')
    return {'name': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def exact(obj, keys):
    if type(obj) is not dict or set(obj) != set(keys.split()):
        raise ValueError('unexpected or missing fields')


def hexhash(x):
    if type(x) is not str or re.fullmatch('[0-9a-f]{64}', x) is None:
        raise ValueError('invalid sha256')


def descriptors(bundle):
    yield bundle['instruction']
    yield from bundle['approved_inputs']
    for event in bundle['tools']:
        yield event['request']
        yield event['response']
    yield bundle['final_output']


def validate(bundle, artifacts=None):
    canonical(bundle)
    exact(bundle, 'version instruction approved_inputs tools final_output receipt_digest')
    if bundle['version'] != VERSION:
        raise ValueError('unsupported version')
    if type(bundle['approved_inputs']) is not list or type(bundle['tools']) is not list:
        raise ValueError('expected ordered lists')
    for event in bundle['tools']:
        exact(event, 'index tool request response previous event_digest')
    names = set()
    for d in descriptors(bundle):
        exact(d, 'name sha256 size')
        if type(d['name']) is not str or not d['name'] or d['name'] in names:
            raise ValueError('empty or duplicate artifact name')
        names.add(d['name'])
        hexhash(d['sha256'])
        if type(d['size']) is not int or not 0 <= d['size'] <= MAX:
            raise ValueError('invalid content size')
    previous = digest('start', {k: bundle[k] for k in ('instruction', 'approved_inputs')})
    for i, event in enumerate(bundle['tools']):
        if type(event['index']) is not int or event['index'] != i:
            raise ValueError('invalid event index')
        if type(event['tool']) is not str or not event['tool']:
            raise ValueError('invalid tool')
        hexhash(event['previous'])
        hexhash(event['event_digest'])
        if event['previous'] != previous:
            raise ValueError('broken event chain')
        if event['event_digest'] != digest('tool', {k: v for k, v in event.items() if k != 'event_digest'}):
            raise ValueError('event digest mismatch')
        previous = event['event_digest']
    hexhash(bundle['receipt_digest'])
    if bundle['receipt_digest'] != digest('bundle', {k: v for k, v in bundle.items() if k != 'receipt_digest'}):
        raise ValueError('receipt digest mismatch')
    checked = 0
    if artifacts is not None:
        if type(artifacts) is not dict or not set(artifacts) <= names:
            raise ValueError('unexpected artifacts')
        for d in descriptors(bundle):
            if d['name'] in artifacts:
                if descriptor(d['name'], artifacts[d['name']]) != d:
                    raise ValueError('artifact content mismatch')
                checked += 1
    return {'artifact': 'verified' if checked == len(names) else 'unverified_source',
            'chain': 'verified_local_hash_chain', 'signature': 'unverified_source',
            'batch': 'unverified_source', 'inclusion': 'unverified_source',
            'artifacts_checked': checked, 'artifacts_required': len(names),
            'authenticated_execution': False}


def build(instruction, approved_inputs, tools, final_output):
    """Descriptors in; tools are (tool_name, request_descriptor, response_descriptor)."""
    b = {'version': VERSION, 'instruction': instruction, 'approved_inputs': approved_inputs,
         'tools': [], 'final_output': final_output}
    previous = digest('start', {'instruction': instruction, 'approved_inputs': approved_inputs})
    for i, (tool, request, response) in enumerate(tools):
        event = dict(index=i, tool=tool, request=request, response=response, previous=previous)
        previous = event['event_digest'] = digest('tool', event)
        b['tools'].append(event)
    b['receipt_digest'] = digest('bundle', b)
    validate(b)
    # Independent result; caller mutations cannot mutate this constructed bundle indirectly.
    return json.loads(canonical(b))


def loads(text):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ValueError('duplicate JSON key')
            obj[k] = v
        return obj
    def bad_constant(value):
        raise ValueError('invalid JSON constant: ' + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: receipt_contract.py bundle.json')
        with open(sys.argv[1], encoding='utf-8') as f:
            result = validate(loads(f.read()))
        print(json.dumps(result, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(1)
