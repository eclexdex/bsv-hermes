"""Offline bounded projections. No filesystem, network, execution or authorization."""
import hashlib
import json
import re

MAX_BYTES = 65536
HEX = re.compile(r'^[0-9a-f]{64}$')

class Invalid(ValueError):
    def __init__(self): super().__init__('invalid_evidence')

def bounded(value):
    try:
        # Count canonical ASCII JSON before allocating its serialized form.
        remaining = MAX_BYTES
        nodes = 0
        def spend(size):
            nonlocal remaining
            remaining -= size
            if remaining < 0: raise Invalid()
        def visit(item, depth=0):
            nonlocal nodes
            nodes += 1
            if depth > 32 or nodes > 8192: raise Invalid()
            kind = type(item)
            if kind is str:
                if len(item) > remaining: raise Invalid()
                spend(2)
                for char in item:
                    point = ord(char)
                    spend(2 if char in '\"\\\\\b\f\n\r\t' else 6 if point < 32 or 127 <= point <= 65535 else 12 if point > 65535 else 1)
            elif kind is dict:
                if len(item) > 8192 - nodes: raise Invalid()
                spend(2 + max(0, len(item)-1) + len(item))
                for key, child in item.items():
                    if type(key) is not str: raise Invalid()
                    visit(key, depth+1); visit(child, depth+1)
            elif kind is list:
                if len(item) > 8192 - nodes: raise Invalid()
                spend(2 + max(0, len(item)-1))
                for child in item: visit(child, depth+1)
            elif item is None: spend(4)
            elif kind is bool: spend(4 if item else 5)
            elif kind is int:
                if item.bit_length() > MAX_BYTES: raise Invalid()
                spend(len(str(item)))
            elif kind is float:
                spend(len(json.dumps(item, allow_nan=False)))
            else: raise Invalid()
        visit(value)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(raw) > MAX_BYTES: raise Invalid()
        return raw
    except (ValueError, TypeError, RecursionError): raise Invalid() from None

def fields(value, keys):
    bounded(value)
    if type(value) is not dict or set(value) != set(keys): raise Invalid()

def digest(value):
    if type(value) is not str or not HEX.fullmatch(value): raise Invalid()
    return value

def integer(value, maximum=2**53-1):
    if type(value) is not int or not 0 <= value <= maximum: raise Invalid()
    return value

def network(value):
    if value not in ('mainnet', 'testnet'): raise Invalid()

def commit(domain, value):
    return hashlib.sha256(b'hermes-assurance/v1\x00' + domain.encode('ascii') + b'\x00' + bounded(value)).hexdigest()

def envelope(kind, projection):
    return {'version':1, 'kind':kind, 'projection':projection, 'digest':commit(kind, projection)}

def artifact(value):
    fields(value, ('network','items','nonce'))
    network(value['network']); digest(value['nonce'])
    if type(value['items']) is not list or not 1 <= len(value['items']) <= 128: raise Invalid()
    for item in value['items']:
        fields(item, ('digest','bytes')); digest(item['digest']); integer(item['bytes'])
    return envelope('artifact', value)

def chain(value):
    fields(value, ('network','events','nonce')); network(value['network']); digest(value['nonce'])
    if type(value['events']) is not list or not 1 <= len(value['events']) <= 128: raise Invalid()
    pending = set(); seen = set(); links = []; previous = '0'*64
    for event in value['events']:
        fields(event, ('call_digest','phase','outcome')); call = digest(event['call_digest'])
        if event['phase'] == 'attempt' and event['outcome'] == 'pending' and call not in seen:
            seen.add(call); pending.add(call)
        elif event['phase'] == 'terminal' and event['outcome'] in ('ok','error','denied','cancelled','unknown') and call in pending:
            pending.remove(call)
        else: raise Invalid()
        previous = commit('tool-chain-link', {'previous':previous,'event':event,'index':len(links),'network':value['network'],'nonce':value['nonce']})
        links.append(previous)
    result = envelope('tool-chain', value)
    result.update(links=links, head=previous, pending_count=len(pending))
    return result

def verify_chain(value):
    # Receipt equality is canonical-byte equality, not Python scalar equality:
    # True/1 and 0.0/0 have different JSON encodings and must not match.
    try: return bounded(value) == bounded(chain(value['projection']))
    except (Invalid, KeyError, TypeError): return False

def validate_shape(value, schema):
    """Validate the closed, dependency-free subset used by the shipped gate schema."""
    kind = schema.get('type')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']): raise Invalid()
    if 'enum' in schema and value not in schema['enum']: raise Invalid()
    if kind == 'object':
        if type(value) is not dict: raise Invalid()
        properties = schema['properties']
        if not set(schema.get('required', ())) <= set(value) or set(value) - set(properties): raise Invalid()
        for key, child in value.items(): validate_shape(child, properties[key])
    elif kind == 'array':
        if type(value) is not list or not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 8192): raise Invalid()
        for child in value: validate_shape(child, schema['items'])
    elif kind == 'integer':
        integer(value, schema.get('maximum', 2**53-1))
        if value < schema.get('minimum', 0): raise Invalid()
    elif kind == 'string':
        if type(value) is not str: raise Invalid()
        if 'pattern' in schema: digest(value)

def gate(value):
    from .contracts import SCHEMAS
    bounded(value)
    validate_shape(value, SCHEMAS['deployment_gate'])
    fields(value, ('network','artifact','chain','required_digests','max_age','observed_at','now'))
    network(value['network']); integer(value['max_age'],86400); integer(value['observed_at']); integer(value['now'])
    required=value['required_digests']
    if type(required) is not list or not 1<=len(required)<=128: raise Invalid()
    for d in required: digest(d)
    a=value['artifact']; c=value['chain']
    try:
        integrity=artifact(a['projection'])==a and verify_chain(c)
        matches=a['projection']['network']==c['projection']['network']==value['network']
        present={item['digest'] for item in a['projection']['items']}
        complete=set(required)<=present and c['pending_count']==0 and all(e['outcome']=='ok' for e in c['projection']['events'] if e['phase']=='terminal')
    except (Invalid,KeyError,TypeError): integrity=matches=complete=False
    fresh=0<=value['now']-value['observed_at']<=value['max_age']
    return {'evidence_ready':integrity and matches and complete and fresh,'integrity':integrity,'network_matches':matches,'complete':complete,'fresh_supplied_timestamp':fresh,'mode':'advisory_only','deployment_safety':'not_certified','bundle_digest':commit('deployment-bundle',value)}

def approval(value):
    fields(value, ('intent','token','now','used_nonces'))
    intent = value['intent']; token = value['token']
    fields(intent, ('network','action_digest','nonce','issued_at','expires_at'))
    fields(token, ('intent_digest','nonce'))
    network(intent['network']); digest(intent['action_digest']); digest(intent['nonce'])
    digest(token['intent_digest']); digest(token['nonce'])
    now = integer(value['now']); start = integer(intent['issued_at']); end = integer(intent['expires_at'])
    if end <= start or end-start > 86400: raise Invalid()
    used = value['used_nonces']
    if type(used) is not list or len(used)>128: raise Invalid()
    for nonce in used: digest(nonce)
    match = token['intent_digest'] == commit('approval-intent',intent) and token['nonce']==intent['nonce'] and start<=now<end and intent['nonce'] not in used
    return {'evidence_matches':match,'intent_digest':commit('approval-intent',intent),'human_consent':'not_authenticated','replay_scope':'supplied_snapshot_only','nonce_to_record':intent['nonce'] if match else None}

