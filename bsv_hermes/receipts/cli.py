"""BSV Hermes offline receipts: create, verify, batch, view. No signing or network."""
import argparse
import json
import os
from pathlib import Path
import sys
from . import evidence, producer, verifier, viewer


def load(path):
    return verifier.strict_load(verifier.read_regular(path, verifier.MAX_JSON))


def write_new(path, raw):
    """Exclusive private output, pinned no-follow ancestors; parent must exist."""
    if '..' in Path(path).parts:
        raise ValueError('traversal in output path')
    path = Path(os.path.abspath(os.fspath(path)))
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = new
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush(); os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('create', 'verify', 'batch', 'view'):
        p = sub.add_parser(name)
        p.add_argument('input', help='explicit caller-approved JSON file, not a directory/archive')
        p.add_argument('--output', help='new private file; parent exists, no overwrite or symlinks')
        if name == 'verify':
            p.add_argument('--artifact', action='append', default=[], metavar='NAME=EXACT_APPROVED_PATH')
            p.add_argument('--trusted-key', help='caller-trusted raw Ed25519 public key, lowercase hex')
            p.add_argument('--now', type=int, help='explicit Unix seconds for signature freshness')
            p.add_argument('--batch-commitment', help='caller-selected bsv-hermes-receipt-batch/1 commitment')
            p.add_argument('--expected-txid')
            p.add_argument('--trusted-header')
            p.add_argument('--commitment', help='expected OP_RETURN push; not automatically a receipt binding')
        elif name == 'batch':
            p.add_argument('--export-private-proofs', action='store_true', default=False)
            p.add_argument('--workflow-id', help='produce inert bsv_publish_prepare arguments; does not call it')
    args = parser.parse_args(argv)
    try:
        value = load(args.input)
        if args.command == 'create':
            result = producer.build_run(value)['bundle']
        elif args.command == 'verify':
            grants = {}
            for item in args.artifact:
                name, sep, path = item.partition('=')
                if not sep or not name or not path or name in grants:
                    raise ValueError('invalid or duplicate file grant')
                grants[name] = path
            result = evidence.verify(value, grants, trusted_key=args.trusted_key, now=args.now,
                batch_commitment=args.batch_commitment, expected_txid=args.expected_txid,
                trusted_header=args.trusted_header, commitment=args.commitment)
        elif args.command == 'batch':
            verifier.fields(value, ('receipts', 'network'))
            if type(value['receipts']) is not list:
                raise ValueError('ordered receipt list required')
            for item in value['receipts']:
                verifier.fields(item, ('id', 'bundle', 'nonce'))
            result = evidence.build_batch([(x['id'], x['bundle']) for x in value['receipts']],
                nonces=[x['nonce'] for x in value['receipts']], network=value['network'],
                export_private_proofs=args.export_private_proofs, workflow_id=args.workflow_id)
        else:
            result = None
        raw = (viewer.generate(value).encode('utf-8') if args.command == 'view' else
               (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii'))
        if args.output:
            write_new(args.output, raw)
        else:
            sys.stdout.write(raw.decode('utf-8'))
        # Report produced, NOT evidence approval; inspect each dimension.
        return 0
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OSError):
        print(json.dumps({'error': 'invalid_input_or_output', 'report_produced': False}), file=sys.stderr)
        return 2


def verify_main():
    return main(['verify'] + sys.argv[1:])
