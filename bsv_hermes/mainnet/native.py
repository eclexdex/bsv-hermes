"""Opt-in bounded Hermes facade; execution stays in the pinned SDK interpreter."""
import json
import os
from pathlib import Path
import subprocess

from .. import boundary

ID = {'type': 'string', 'minLength': 1, 'maxLength': 96, 'pattern': '[A-Za-z0-9_-]{1,96}'}
OPERATIONS = {
    'bsv_wallet_address': ('address', 'Read dedicated mainnet wallet public metadata; no creation.', {}),
    'bsv_funding_status': ('funding_status', 'Bounded public GET funding observation; not SPV or consensus.', {}),
    'bsv_publish_prepare': ('prepare', 'Build exact digest-publication quote; no signing, approval or submission.',
                            {'workflow_id': ID, 'text': {'type': 'string', 'maxLength': 4096}}),
    'bsv_publish_sign': ('sign', 'Sign frozen quote only after separate operator approval and durable budget locks.', {'workflow_id': ID}),
    'bsv_publish_submit': ('submit', 'Submit once only after independent exact-txid operator approval; no retries.', {'workflow_id': ID}),
    'bsv_publish_status': ('status', 'Read local workflow and durable budget status without provider calls.', {'workflow_id': ID}),
    'bsv_publish_receipt': ('receipt', 'Reconcile exact txid readback; never sign, resend or release held budget.', {'workflow_id': ID}),
    'bsv_spend_policy_status': ('policy_status', 'Read fixed operator session and shared aggregate spending cap.', {}),
}


def schema(name):
    method, description, properties = OPERATIONS[name]
    return {'name': name, 'description': description, 'parameters': {
        'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}}


def error(code):
    return {'ok': False, 'error': {'code': code,
            'message': 'Mainnet operation unavailable or rejected. Inspect local status; never retry an uncertain submission.'}}


def tool_specs(directory=None, python=None):
    # Captured trusted settings, never per-call kwargs. Registration performs no I/O.
    def handler(name):
        def run(arguments, **ignored):
            if not (type(directory) is str and Path(directory).is_absolute()
                    and type(python) is str and Path(python).is_absolute()):
                return json.dumps(error('mainnet_not_configured'))
            try:
                # -I excludes user-site/PYTHONPATH. No shell or inherited credential environment.
                env = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'TMPDIR')}
                result = subprocess.run([python, '-I', '-B', str(Path(__file__).with_name('worker.py')), directory],
                    input=json.dumps({'tool': name, 'arguments': arguments}).encode(), stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, env=env, timeout=100, check=False)
                if result.returncode or len(result.stdout) > 262144:
                    return json.dumps(error('mainnet_worker_failed'))
                response = json.loads(result.stdout)
                boundary.budget(response)
                if type(response) is not dict or type(response.get('ok')) is not bool:
                    return json.dumps(error('mainnet_worker_failed'))
                return json.dumps(response)
            except subprocess.TimeoutExpired:
                return json.dumps(error('mainnet_timeout_reconcile_only'))
            except (OSError, ValueError, TypeError, RecursionError):
                return json.dumps(error('mainnet_worker_failed'))
        return run
    return {name: (boundary.native(handler(name), schema(name)['parameters']), schema(name)) for name in OPERATIONS}
