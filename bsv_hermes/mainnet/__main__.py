"""Operator CLI. Keep init/approve commands outside model-accessible tools."""
import argparse
import importlib.metadata
import json
import sys

from .native import error
from .worker import safe_error


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def doctor():
    versions = {}
    for name in ('bsv-sdk', 'cryptography'):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return {'sdk_expected': '2.4.0', 'cryptography_expected': '48.0.0', 'installed': versions,
            'pins_match': versions == {'bsv-sdk': '2.4.0', 'cryptography': '48.0.0'},
            'wallet_opened': False, 'ready_for_mainnet': False,
            'note': 'Dependency metadata only. Operator provisioning, isolation, fresh funding and separate approvals required.'}


def main(argv=None):
    parser = Parser(prog='bsv-mainnet', description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
    sub.add_parser('doctor', help='Offline dependency metadata, no wallet or backend access.')
    for name in ('init', 'address', 'funding', 'prepare', 'review', 'approve-sign', 'sign',
                 'approve-submit', 'submit', 'status', 'receipt', 'policy'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--directory', required=True, help='Operator-bound dedicated runtime, absolute path.')
        if name in ('init', 'approve-sign', 'approve-submit'):
            cmd.add_argument('--authority-directory', required=True, help='Separate operator-only authority; never a secret value.')
        if name == 'init':
            cmd.add_argument('--create-dedicated-wallet', required=True, action='store_true')
            cmd.add_argument('--total-cap-sat', type=int, required=True)
            cmd.add_argument('--max-fee-sat', type=int, required=True)
            cmd.add_argument('--fee-rate-sat-kb', type=int, required=True)
        elif name not in ('address', 'funding', 'policy'):
            cmd.add_argument('--workflow-id', required=True)
        if name == 'approve-sign':
            cmd.add_argument('--expected-digest', required=True)
            cmd.add_argument('--max-cost-sat', type=int, required=True)
        if name == 'approve-submit':
            cmd.add_argument('--expected-txid', required=True)
    try:
        args = vars(parser.parse_args(argv)); command = args.pop('command')
        if command == 'doctor':
            result = doctor()
        elif command in ('init', 'approve-sign', 'approve-submit'):
            from . import operator
            args.pop('create_dedicated_wallet', None)
            result = getattr(operator, {'init': 'initialize', 'approve-sign': 'approve_sign',
                                       'approve-submit': 'approve_submit'}[command])(**args)
        else:
            from .runtime import Runtime
            runtime = Runtime(args.pop('directory'))
            if command == 'prepare':
                text = sys.stdin.buffer.read(4097)
                if len(text) > 4096:
                    raise ValueError('content_limit')
                args['text'] = text.decode('utf-8')
            result = getattr(runtime, {'funding': 'funding_status', 'policy': 'policy_status'}.get(command, command))(**args)
        response = {'ok': True, 'result': result}
    except Exception as exc:
        response = safe_error(exc)
    print(json.dumps(response, separators=(',', ':')))
    return 0 if response['ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
