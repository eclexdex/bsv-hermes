import json
import unittest
try:
    from bsv_hermes import adapter
except ImportError:
    adapter = None

class FacadeTests(unittest.TestCase):
    def test_handlers_revalidate_arguments_and_bound_errors(self):
        handlers = [(adapter.capabilities, {}), (adapter.inspect_script, {'script_hex': '00'}),
                    (adapter.inspect_transaction, {'transaction_hex': '0100000001' + '00' * 32 + 'ffffffff00ffffffff01e803000000000000015100000000'}),
                    (adapter.plan_commitment, {'text': 'hello'})]
        for handler, valid in handlers:
            self.assertTrue(json.loads(handler(valid, task_id='ignored'))['ok'])
            invalid = [None, [], True, 'secret-data', dict(valid, unknown='secret-data')]
            if valid:
                invalid += [{}, {next(iter(valid)): None}, {next(iter(valid)): True}]
            if handler is adapter.inspect_script:
                invalid += [{'script_hex': 'PRIVATE-NOT-HEX'}, {'script_hex': '00', 'max_items': True}]
            for value in invalid:
                with self.subTest(handler=handler.__name__, kind=type(value).__name__):
                    raw = handler(value)
                    result = json.loads(raw)
                    self.assertFalse(result['ok'])
                    self.assertEqual(result['error']['code'], 'invalid_input')
                    self.assertLess(len(raw), 350)
                    self.assertNotIn('secret-data', raw)
                    self.assertNotIn('PRIVATE', raw)

    def test_registration_schemas_and_handlers(self):
        self.assertTrue(hasattr(adapter, 'register'), 'registrar missing')
        class Context:
            def __init__(self):
                self.tools = {}
                self.skills = {}
            def register_tool(self, **kwargs):
                self.tools[kwargs['name']] = kwargs
                return object()
            def get_config(self, key, default=None):
                return default
            def register_skill(self, name, path, **kwargs):
                self.skills[name] = path
        ctx = Context()
        adapter.register(ctx)
        self.assertEqual(len(ctx.tools), 6)
        self.assertEqual(set(ctx.skills), {'inspect-evidence', 'plan-commitment', 'audit-workproducts'})
        for name, tool in ctx.tools.items():
            self.assertEqual(tool['toolset'], 'bsv')
            self.assertEqual(tool['schema']['name'], name)
            self.assertFalse(tool['schema']['parameters']['additionalProperties'])
            self.assertEqual(tool['schema']['parameters']['type'], 'object')
        cases = [('bsv_capabilities', {}, 'implemented'),
                 ('bsv_inspect_script', {'script_hex': '006a'}, 'operation_count'),
                 ('bsv_plan_commitment', {'text': 'hello'}, 'digest_hex')]
        for name, args, field in cases:
            value = json.loads(ctx.tools[name]['handler'](args))
            self.assertTrue(value['ok'])
            self.assertIn(field, value['result'])
        for path in ctx.skills.values():
            self.assertTrue(path.is_file())

class CapabilityTests(unittest.TestCase):
    def test_implemented_and_planned_are_separate(self):
        self.assertIsNotNone(adapter, 'native adapter missing')
        result = json.loads(adapter.capabilities({}))
        self.assertTrue(result['ok'])
        self.assertEqual(set(result['result']['implemented']), {'bsv_capabilities', 'bsv_inspect_script', 'bsv_inspect_transaction', 'bsv_plan_commitment', 'bsv_identity_soul', 'bsv_assurance_artifact'})
        self.assertNotIn('planned', result['result'])
        for capability in ('network', 'signing', 'payments', 'broadcast'):
            self.assertFalse(result['result'][capability])
