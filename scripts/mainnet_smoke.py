"""Actual native registry + isolated SDK process + loopback-only end-to-end.

Run with a Hermes host interpreter and --sdk-python pointing to the separately
pinned mainnet environment. Never uses live profile, real coins or external POST.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from hermes_cli.plugin_dev import doctor_plugin, _doctor_runtime
from tools.registry import registry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', default='.')
    parser.add_argument('--sdk-python', required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    sdk = Path(args.sdk_python).absolute()
    commands = []
    with tempfile.TemporaryDirectory(prefix='bsv-mainnet-native-') as temp:
        work = Path(temp)
        clean = work/'bsv-hermes'
        shutil.copytree(source, clean, ignore=shutil.ignore_patterns('.git', 'local-verification', 'build',
                        'dist', '*.egg-info', '__pycache__', '*.pyc', '.venv'))
        environment = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'TMPDIR')}
        environment.update(HOME=str(work), HERMES_HOME=str(work/'unused-profile'), PYTHONDONTWRITEBYTECODE='1')

        def cli(*arguments):
            command = [str(sdk), '-B', '-m', 'bsv_hermes.mainnet', *map(str, arguments)]
            p = subprocess.run(command, cwd=clean, env=environment, capture_output=True, text=True, timeout=30)
            commands.append({'argv': command, 'cwd': str(clean), 'exit_code': p.returncode,
                             'stdout': p.stdout, 'stderr': p.stderr})
            assert p.returncode == 0, p.stdout+p.stderr
            return json.loads(p.stdout)['result']

        runtime, authority = work/'runtime', work/'operator-only'
        public = cli('init', '--directory', runtime, '--authority-directory', authority,
                     '--total-cap-sat', '300', '--max-fee-sat', '150', '--fee-rate-sat-kb', '500',
                     '--create-dedicated-wallet')
        # Test helper is part of the sdist, not the runtime wheel.
        sys.path[:0] = [str(clean/'tests'), str(clean)]
        from mainnet_fixtures import Provider
        provider = Provider(public)
        try:
            # Trusted TEST transport injection only; no test provider setting exists in the product.
            worker = work/'loopback-worker.py'
            worker.write_text('''import sys
from pathlib import Path
from http.client import HTTPConnection
from urllib.parse import urlsplit
sys.path.insert(0, SOURCE)
from bsv_hermes.mainnet.runtime import Runtime
from bsv_hermes.mainnet.worker import main
from bsv_hermes.mainnet.funding import FundingClient, HTTPReply
from bsv_hermes.mainnet.broadcast.transport import HTTPTransport

def funding(url, *, timeout, max_bytes):
    connection = HTTPConnection('127.0.0.1', PORT, timeout=timeout)
    try:
        connection.request('GET', urlsplit(url).path)
        response = connection.getresponse()
        return HTTPReply(response.status, response.read(max_bytes+1), {k.lower(): v for k,v in response.getheaders()})
    finally:
        connection.close()

def factory(directory):
    return Runtime(directory, funding_client=FundingClient(transport=funding, request_interval=0),
                   broadcast_transport=HTTPTransport.for_local_tests('http://127.0.0.1:PORT'))
sys.argv = [sys.argv[-2], sys.argv[-1]]
main(factory)
'''.replace('SOURCE', repr(str(clean))).replace('PORT', str(provider.server.server_port)))
            launcher = work/'test-sdk-python'
            launcher.write_text('#!/bin/sh\nexec ' + shlex.quote(str(sdk)) + ' -I -B ' + shlex.quote(str(worker)) + ' "$@"\n')
            launcher.chmod(0o700)
            report = doctor_plugin(clean)
            assert report.ok and not report.findings, report.format_text()
            results = {}; invalid_count = 0
            with _doctor_runtime(clean) as host:
                assert len(host.manager._plugin_tool_names) == 6
                assert len(host.manager._plugin_skills) == 3
                host.manager.unload()
                config = Path(os.environ['HERMES_HOME'])/'config.yaml'
                config.write_text(json.dumps({'plugins': {'entries': {'bsv-hermes': {'settings': {
                    'enabled_kits': ['mainnet'], 'mainnet_directory': str(runtime), 'mainnet_python': str(launcher)}}}}}))
                host.manager._load_plugin(host.manifest)
                from bsv_hermes.mainnet.native import OPERATIONS
                names = set(host.manager._plugin_tool_names)
                assert len(names) == 14 and set(OPERATIONS) <= names
                for item in host.manager._plugin_skills.values():
                    assert item['path'].is_file() and str(item['path']).startswith(os.environ['HERMES_HOME'])
                def call(name, arguments):
                    raw = registry.dispatch(name, arguments, scope=host.manager.scope_key,
                                            task_id='synthetic-loopback', session_id='not-authority')
                    assert type(raw) is str
                    value = json.loads(raw)
                    assert value['ok'], (name, value)
                    assert 'private_key' not in raw and 'signed_transaction_hex' not in raw
                    results[name] = value['result']
                    return value['result']
                call('bsv_wallet_address', {})
                call('bsv_funding_status', {})
                from bsv_hermes.receipts.producer import build_run
                from bsv_hermes.receipts.evidence import build_batch
                bundle = build_run({'run_id':'synthetic', 'instruction':{'id':'instruction','bytes_b64':'YWJj'},
                    'approved_inputs':[], 'tools':[], 'final_output':{'id':'output','bytes_b64':''}})['bundle']
                batch = build_batch([('synthetic',bundle)], nonces=['01'*32], workflow_id='native')
                request = batch['publication_request']
                quote = call('bsv_publish_prepare', request['arguments'])
                assert quote['digest_hex'] == request['expected_text_sha256']
                cli('approve-sign', '--directory', runtime, '--authority-directory', authority,
                    '--workflow-id', 'native', '--expected-digest', quote['signing_digest'], '--max-cost-sat', '150')
                signed = call('bsv_publish_sign', {'workflow_id': 'native'})
                cli('approve-submit', '--directory', runtime, '--authority-directory', authority,
                    '--workflow-id', 'native', '--expected-txid', signed['txid'])
                submitted = call('bsv_publish_submit', {'workflow_id': 'native'})
                assert submitted['stage'] == 'submitted'
                assert submitted['observation']['readback']['raw_txid_verified'] is True
                call('bsv_publish_status', {'workflow_id': 'native'})
                receipt = call('bsv_publish_receipt', {'workflow_id': 'native'})
                call('bsv_spend_policy_status', {})
                assert set(results) == set(OPERATIONS)
                assert receipt['txid'] == signed['txid'] and provider.posts == 1
                call('bsv_publish_submit', {'workflow_id': 'native'})
                assert provider.posts == 1
                for name in OPERATIONS:
                    for invalid in (None, [], True, {'approved': True}, {'workflow_id': 'native', 'path': 'PRIVATE-CANARY'}):
                        raw = registry.dispatch(name, invalid, scope=host.manager.scope_key)
                        value = json.loads(raw)
                        assert not value['ok'] and value['error']['code'] == 'invalid_input'
                        assert 'PRIVATE-CANARY' not in raw
                        invalid_count += 1
                caps = call('bsv_capabilities', {})
                assert caps['mainnet']['configured'] and not caps['mainnet']['ready_for_mainnet']
            result = {'doctor_ok': True, 'registered_tools': sorted(names), 'skills': 3,
                      'actual_dispatch': 'registry.dispatch', 'sdk_worker': 'real isolated subprocess; trusted loopback adapters only',
                      'added_tools_valid_dispatch': len(OPERATIONS), 'invalid_dispatches': invalid_count,
                      'local_posts': provider.posts, 'public_posts': 0, 'mainnet_spent_sat': 0,
                      'txid': receipt['txid'], 'receipt': receipt, 'results': results, 'commands': commands,
                      'batch_publication_request': request, 'receipt_batch': batch['manifest']}
        finally:
            provider.close()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
