"""Single native Hermes facade. Domain protocols retain their original bytes."""
import json
from pathlib import Path
from . import domain, boundary
from .kits.identity import operations as identity
from .kits.assurance import operations as assurance
from .kits.integrations import operations as integrations

GROUPS = ('identity', 'assurance', 'integrations', 'mainnet')


def _invoke(arguments, function, required, optional=()):
    try:
        if type(arguments) is not dict or set(arguments) - set(required) - set(optional) or not set(required) <= set(arguments):
            raise ValueError('invalid fields')
        return json.dumps({'ok': True, 'result': function(**arguments)})
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return json.dumps({'ok': False, 'error': {'code': 'invalid_input', 'message': 'Input rejected by bounded tool contract.'}})


def inspect_script(arguments, **kwargs):
    return _invoke(arguments, domain.inspect_script, ('script_hex',), ('max_items',))


def inspect_transaction(arguments, **kwargs):
    return _invoke(arguments, domain.inspect_transaction, ('transaction_hex',), ('max_items',))


def plan_commitment(arguments, **kwargs):
    return _invoke(arguments, domain.plan_commitment, ('text',))


def _kit_handler(execute):
    def run(arguments, **kwargs):
        value = execute(arguments)
        if not value['ok']:
            return json.dumps({'ok': False, 'error': {'code': 'invalid_input', 'message': 'Input rejected by bounded tool contract.'}})
        return json.dumps({'ok': True, 'result': value['data'], 'warnings': value.get('warnings', [])})
    return run


def _batch(arguments):
    export = arguments.get('export_private_proofs', False)
    value = integrations.dispatch('batch', {k: v for k, v in arguments.items() if k != 'export_private_proofs'})
    if value['ok']:
        if not export:
            value['data'].pop('proofs', None)
        value['warnings'].append('Batch proofs permit offline guesses and correlation of low-entropy leaves despite root salting. Keep exported proofs private; publish only the final commitment if hiding is required.')
    return value


LIMIT = {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 20}
TOOLS = {
    'bsv_inspect_script': (inspect_script, 'Disassemble bounded untrusted Script without execution.',
                           {'script_hex': {'type': 'string', 'maxLength': 20000}, 'max_items': LIMIT}, ['script_hex']),
    'bsv_inspect_transaction': (inspect_transaction, 'Inspect bounded legacy transaction bytes; no chain or validity claims.',
                               {'transaction_hex': {'type': 'string', 'maxLength': 200000}, 'max_items': LIMIT}, ['transaction_hex']),
    'bsv_plan_commitment': (plan_commitment, 'Plan unsigned SHA256 UTF-8 commitment, not a transaction.',
                            {'text': {'type': 'string', 'maxLength': 4096}}, ['text']),
}
SKILLS = ('inspect-evidence', 'plan-commitment', 'audit-workproducts')


def _selected(groups):
    if type(groups) is not list or any(type(g) is not str or g not in GROUPS for g in groups) or len(set(groups)) != len(groups):
        raise ValueError('enabled_kits must be a unique list from identity, assurance, integrations, mainnet')
    return sorted(groups)


def tool_specs(groups=None, *, mainnet_directory=None, mainnet_python=None):
    groups = _selected([] if groups is None else groups)
    tools = {}
    for name, (handler, description, properties, required) in TOOLS.items():
        tools[name] = (handler, {'name': name, 'description': description, 'parameters': {
            'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}})
    tools['bsv_identity_soul'] = (_kit_handler(lambda a: identity.execute('soul', a)), identity.schema('soul'))
    name = 'bsv_assurance_artifact'
    tools[name] = (_kit_handler(assurance.handler('artifact')), {'name': name,
        'description': 'Commit supplied workproduct digests; no file reads, execution truth or publication.',
        'parameters': {'type': 'object', 'properties': {'evidence': assurance.SCHEMAS['artifact']},
                       'required': ['evidence'], 'additionalProperties': False}})
    tools['bsv_capabilities'] = (capabilities, {'name': 'bsv_capabilities',
        'description': 'Report actual registered offline tools and configuration.',
        'parameters': {'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False}})
    if 'identity' in groups:
        for kind in ('instructions', 'posture', 'release'):
            tools['bsv_identity_' + kind] = (_kit_handler(lambda a, k=kind: identity.execute(k, a)), identity.schema(kind))
    if 'assurance' in groups:
        from .receipts.native import tool_specs as receipt_specs
        tools.update(receipt_specs())
        for operation in ('tool_chain', 'deployment_gate', 'approval_intent'):
            name = 'bsv_assurance_' + operation
            tools[name] = (_kit_handler(assurance.handler(operation)), {'name': name,
                'description': 'Evaluate supplied ' + operation + ' evidence; never authorization or execution.',
                'parameters': {'type': 'object', 'properties': {'evidence': assurance.SCHEMAS[operation]},
                               'required': ['evidence'], 'additionalProperties': False}})
    if 'integrations' in groups:
        for action, schema in integrations.SCHEMAS.items():
            tools[schema['name']] = (_kit_handler(lambda a, action=action: integrations.dispatch(action, a)), schema)
        import copy
        batch_schema = copy.deepcopy(integrations.SCHEMAS['batch'])
        batch_schema['parameters']['properties']['export_private_proofs'] = {
            'type': 'boolean', 'default': False, 'description': 'Explicit private proof export; proofs permit guessing and correlation.'}
        batch_schema['description'] = 'Create v1 ordered Merkle commitment. Proofs omitted unless explicitly exported privately.'
        tools['bsv_int_batch'] = (_kit_handler(_batch), batch_schema)
    if 'mainnet' in groups:
        from .mainnet.native import tool_specs as mainnet_specs
        tools.update(mainnet_specs(mainnet_directory, mainnet_python))
    return {name: (boundary.native(handler, schema['parameters']), schema) for name, (handler, schema) in tools.items()}


def _capabilities(names=None, groups=None, mainnet_settings=None):
    enabled = groups is not None and 'mainnet' in groups
    result = {'implemented': sorted(tool_specs() if names is None else names),
              'enabled_kits': [] if groups is None else list(groups), 'available_kits': list(GROUPS),
              'network': enabled, 'signing': enabled, 'payments': False, 'broadcast': enabled}
    if enabled:
        settings = mainnet_settings or {}
        result['mainnet'] = {'configured': all(type(settings.get(k)) is str and Path(settings[k]).is_absolute()
                    for k in ('mainnet_directory', 'mainnet_python')), 'ready_for_mainnet': False,
                    'authorization': 'independent_operator_sign_and_submit_grants',
                    'scope': 'dedicated P2PKH digest publication only; flags denote available operations, not authority'}
    return result


def capabilities(arguments, **kwargs):
    return _invoke(arguments, _capabilities, ())


def register(ctx):
    groups = _selected(ctx.get_config('enabled_kits', []))
    mainnet_settings = {}
    if 'mainnet' in groups:
        mainnet_settings = {'mainnet_directory': ctx.get_config('mainnet_directory', None),
                            'mainnet_python': ctx.get_config('mainnet_python', None)}
    specs = tool_specs(groups, **mainnet_settings)
    registered, handles = [], []
    specs['bsv_capabilities'] = (
        boundary.native(lambda args, **kw: _invoke(args, lambda: _capabilities(registered, groups, mainnet_settings), ()), specs['bsv_capabilities'][1]['parameters']),
        specs['bsv_capabilities'][1])
    try:
        for name, (handler, schema) in specs.items():
            handle = ctx.register_tool(name=name, toolset='bsv', handler=handler, schema=schema, override=False)
            if handle is None:
                raise RuntimeError('BSV tool registration conflict: ' + name)
            handles.append(handle)
            registered.append(name)
        for name in SKILLS:
            handles.append(ctx.register_skill(name, Path(__file__).parent / 'skills' / name / 'SKILL.md',
                description='Offline supplied-evidence workflow; no custody or publication.'))
    except Exception:
        for handle in reversed(handles):
            if hasattr(handle, 'dispose'):
                handle.dispose()
        raise
