"""Common native JSON budget/schema boundary; never changes protocol preimages."""
import json
import re

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_STRING = 200000
MAX_DEPTH = 32
MAX_NODES = 20000
ERROR = {'ok': False, 'error': {'code': 'invalid_input', 'message': 'Input rejected by bounded tool contract.'}}


def budget(value):
    remaining, nodes = MAX_JSON_BYTES, 0
    def spend(size):
        nonlocal remaining
        remaining -= size
        if remaining < 0: raise ValueError('budget')
    def visit(item, depth=0):
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES: raise ValueError('structure')
        kind = type(item)
        if kind is str:
            if len(item) > min(MAX_STRING, remaining): raise ValueError('string')
            spend(2)
            for char in item:
                cp=ord(char)
                spend(2 if char in '"\\\b\f\n\r\t' else 6 if cp<32 or 127<=cp<=65535 else 12 if cp>65535 else 1)
        elif kind is dict:
            if len(item) > MAX_NODES-nodes: raise ValueError('nodes')
            spend(2+len(item)+max(0,len(item)-1))
            for key, child in item.items():
                if type(key) is not str: raise ValueError('key')
                visit(key,depth+1); visit(child,depth+1)
        elif kind is list:
            if len(item) > MAX_NODES-nodes: raise ValueError('nodes')
            spend(2+max(0,len(item)-1))
            for child in item: visit(child,depth+1)
        elif item is None: spend(4)
        elif kind is bool: spend(4 if item else 5)
        elif kind is int and abs(item)<=9007199254740991: spend(len(str(item)))
        else: raise ValueError('type')
    visit(value)


def validate(value, schema):
    typ = schema.get('type')
    types = {'object':dict, 'array':list, 'string':str, 'integer':int, 'boolean':bool}
    if typ and type(value) is not types[typ]: raise ValueError('type')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']): raise ValueError('const')
    if 'enum' in schema and not any(type(value) is type(v) and value==v for v in schema['enum']): raise ValueError('enum')
    if typ=='object':
        props=schema.get('properties',{})
        if not set(schema.get('required',[]))<=set(value): raise ValueError('missing')
        if schema.get('additionalProperties') is False and set(value)-set(props): raise ValueError('unknown')
        for k,v in value.items():
            if k in props: validate(v,props[k])
    elif typ=='array':
        if not schema.get('minItems',0)<=len(value)<=schema.get('maxItems',MAX_NODES): raise ValueError('count')
        for v in value: validate(v,schema['items'])
    elif typ=='string':
        if not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',MAX_STRING): raise ValueError('length')
        if 'pattern' in schema and re.fullmatch(schema['pattern'],value) is None: raise ValueError('pattern')
    elif typ=='integer':
        if not schema.get('minimum',-9007199254740991)<=value<=schema.get('maximum',9007199254740991): raise ValueError('range')


def native(handler, schema):
    def run(arguments, **kwargs):
        try:
            budget(arguments)
            validate(arguments, schema)
            return handler(arguments, **kwargs)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
            return json.dumps(ERROR)
    return run
