"""Supplied-evidence native adapter; no file reads, keys or hook activation."""
import json
from .producer import build_run


def handler(arguments, **kwargs):
    try:
        return json.dumps({'ok': True, 'result': build_run(arguments)})
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return json.dumps({'ok': False, 'error': {'code': 'invalid_input', 'message': 'Input rejected by bounded run receipt contract.'}})


def tool_specs():
    return {'bsv_assurance_run': (handler, {
        'name': 'bsv_assurance_run',
        'description': 'Build offline receipt from supplied run evidence; never executes, signs or publishes. Approval and execution unverified.',
        'parameters': {'type': 'object', 'additionalProperties': False,
            'required': ['run_id', 'instruction', 'approved_inputs', 'tools', 'final_output'],
            'properties': {'run_id': {'type': 'string', 'maxLength': 128},
                           'instruction': {'type': 'object'},
                           'approved_inputs': {'type': 'array', 'maxItems': 128, 'items': {'type': 'object'}},
                           'tools': {'type': 'array', 'maxItems': 128, 'items': {'type': 'object'}},
                           'final_output': {'type': 'object'}}}})}
