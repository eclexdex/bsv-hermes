"""Offline receipt report viewer generator; Python standard library only."""
import argparse
import json
from pathlib import Path

MAX_BYTES = 1048576
DIMENSIONS = ('artifact', 'chain', 'signature', 'batch', 'publication', 'inclusion')

def strict_load(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('Import exceeds 1 MiB')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Nonfinite number: ' + value)
    obj = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(obj, dict):
        raise ValueError('Expected JSON object')
    stack = [(obj, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 40 or nodes > 20000:
            raise ValueError('Structure exceeds depth/node budget')
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return obj

def generate(data=None):
    template = Path(__file__).with_name('template.html').read_text()
    serialized = json.dumps(data or {}, ensure_ascii=True, allow_nan=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return template.replace('/*INITIAL_DATA*/{}', serialized)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.input:
        with args.input.open('rb') as stream:
            data = strict_load(stream.read(MAX_BYTES + 1))
    else:
        data = {}
    args.output.write_text(generate(data))

if __name__ == '__main__':
    main()
