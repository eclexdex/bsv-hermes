"""Bounded caller-supplied native API; intentionally no filesystem tool or hooks."""
import base64
import binascii
import json
from . import core

WARNINGS = ['Unsigned digest plan only: not published, signed, timestamped or SPV verified.',
            'Hash equality is not authorship, approval, safe instructions or complete runtime attestation.',
            'Native deterministic commitments permit guessing. Private-opening library workflows require separately secured local storage; no CLI is bundled.']


def decode(value):
    if not isinstance(value, str) or len(value) > 87384:
        raise ValueError('invalid bounded encoding')
    return core.bounded(base64.b64decode(value, validate=True))


def entries(value):
    if not isinstance(value, list) or not 1 <= len(value) <= core.MAX_FILES:
        raise ValueError('invalid bounded entries')
    result = []
    total = 0
    for item in value:
        if not isinstance(item, dict) or set(item) != {'path', 'data_b64'}:
            raise ValueError('invalid entry')
        data = decode(item['data_b64']); total += len(data)
        if total > core.MAX_TOTAL:
            raise ValueError('aggregate input limit')
        result.append({'path': item['path'], 'data': data})
    return result


def preimage(kind, request):
    if not isinstance(request, dict) or kind not in core.KINDS:
        raise ValueError('invalid request')
    content_key = {'soul': 'data_b64', 'instructions': 'entries', 'release': 'entries', 'posture': 'fields'}[kind]
    allowed = {content_key, 'network', 'receipt'}
    if kind == 'release': allowed.add('before')
    if set(request) - allowed or not {content_key, 'network'} <= set(request):
        raise ValueError('unexpected or missing fields')
    network = request['network']
    if network not in ('mainnet', 'testnet'):
        raise ValueError('invalid network')
    if kind == 'soul': return decode(request[content_key])
    if kind == 'posture': return core.posture_preimage(request[content_key])
    return core.manifest_preimage(entries(request[content_key]))


def execute(kind, request):
    try:
        data = preimage(kind, request)
        if 'receipt' in request:
            receipt = request['receipt']
            result = {'matches': isinstance(receipt, dict) and receipt.get('kind') == kind and receipt.get('network') == request['network'] and core.verify(receipt, data)}
        else:
            result, _ = core.seal(data, kind, request['network'])
        if 'before' in request:
            result = {'receipt': result, 'local_changes': core.changes(entries(request['before']), entries(request['entries']))}
        return {'ok': True, 'data': result, 'warnings': WARNINGS}
    except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError, RecursionError):
        return {'ok': False, 'error': {'code': 'INVALID_INPUT', 'message': 'Input rejected by bounded identity contract.'}, 'warnings': WARNINGS}


def schema(kind):
    encoded = {'type': 'string', 'maxLength': 87384, 'description': 'Base64 exact bytes; maximum 65536 decoded bytes.'}
    collection = {'type': 'array', 'minItems': 1, 'maxItems': 128, 'items': {'type': 'object', 'additionalProperties': False, 'required': ['path', 'data_b64'], 'properties': {'path': {'type': 'string', 'maxLength': 240}, 'data_b64': encoded}}}
    fields = {'type': 'object', 'additionalProperties': False, 'required': sorted(core.POSTURE_FIELDS), 'properties': {
        'hermes_version': {'type': 'string', 'pattern': r'^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'},
        'approval_mode': {'enum': ['required', 'disabled', 'unknown']}, 'network_access': {'enum': ['disabled', 'allowlisted', 'unknown']},
        'max_iterations': {'type': 'integer', 'minimum': 1, 'maximum': 10000}, 'telemetry_enabled': {'type': 'boolean'}}}
    key, content = {'soul': ('data_b64', encoded), 'instructions': ('entries', collection), 'release': ('entries', collection), 'posture': ('fields', fields)}[kind]
    props = {key: content, 'network': {'enum': ['mainnet', 'testnet']}, 'receipt': {'type': 'object', 'description': 'Optional public receipt to compare; no chain verification.'}}
    if kind == 'release': props['before'] = collection
    return {'name': 'bsv_identity_' + kind, 'description': 'Offline ' + kind + ' integrity commitment/compare; unsigned plan, no host discovery or chain actions.',
            'parameters': {'type': 'object', 'additionalProperties': False, 'required': [key, 'network'], 'properties': props}}

