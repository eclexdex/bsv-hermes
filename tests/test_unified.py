import json
import unittest
from bsv_hermes import adapter

DEFAULTS = {'bsv_capabilities', 'bsv_inspect_transaction', 'bsv_inspect_script',
            'bsv_plan_commitment', 'bsv_identity_soul', 'bsv_assurance_artifact'}

class Context:
    def __init__(self, groups=None):
        self.tools, self.skills = {}, {}
        self.groups = [] if groups is None else groups
    def get_config(self, key, default=None):
        assert key == 'enabled_kits'
        return self.groups
    def register_tool(self, **kw):
        self.tools[kw['name']] = kw
        return object()
    def register_skill(self, name, path, **kw):
        self.skills[name] = path
        return object()

class UnifiedTests(unittest.TestCase):
    def test_default_six_supplied_content_and_common_envelope(self):
        ctx = Context()
        adapter.register(ctx)
        self.assertEqual(set(ctx.tools), DEFAULTS)
        args = {'data_b64': 'aGVsbG8=', 'network': 'testnet'}
        soul = json.loads(ctx.tools['bsv_identity_soul']['handler'](args))
        self.assertTrue(soul['ok'])
        self.assertEqual(set(soul), {'ok','result','warnings'})
        self.assertEqual(soul['result']['domain'], 'bsv-hermes-identity/v1')
        self.assertFalse(soul['result']['private_nonce'])
        self.assertNotIn('nonce', soul['result'])
        artifact = json.loads(ctx.tools['bsv_assurance_artifact']['handler']({'evidence': {
            'network': 'testnet','items': [{'digest':'a'*64, 'bytes':5}], 'nonce':'b'*64}}))
        self.assertTrue(artifact['ok'])
        self.assertEqual(artifact['result']['version'], 1)
        self.assertNotIn('projection', artifact['result'])
        capabilities = json.loads(ctx.tools['bsv_capabilities']['handler']({}))['result']
        self.assertEqual(set(capabilities['implemented']), DEFAULTS)
        self.assertNotIn('planned', capabilities)
        self.assertEqual(len(ctx.skills), 3)

    def test_opt_in_groups_and_actual_capabilities(self):
        expected = {'identity': 3, 'assurance': 4, 'integrations': 7}
        for group, extra in expected.items():
            ctx = Context([group])
            adapter.register(ctx)
            self.assertEqual(len(ctx.tools), len(DEFAULTS) + extra)
            result = json.loads(ctx.tools['bsv_capabilities']['handler']({}))['result']
            self.assertEqual(set(result['implemented']), set(ctx.tools))
            self.assertEqual(result['enabled_kits'], [group])
            self.assertTrue(all(t['toolset']=='bsv' for t in ctx.tools.values()))
        ctx = Context(list(expected))
        adapter.register(ctx)
        self.assertEqual(len(ctx.tools), 20)
        for config in [True, 'identity', ['unknown'], ['identity','identity'], [3]]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                adapter.register(Context(config))

    def test_comparison_false_is_successful_execution(self):
        ctx=Context(['integrations']); adapter.register(ctx)
        result=json.loads(ctx.tools['bsv_int_content']['handler']({
            'network':'testnet','content_hex':'616263','expected_sha256':'0'*64}))
        self.assertTrue(result['ok'])
        self.assertFalse(result['result']['digest_match'])
        self.assertNotIn('data', result)
        self.assertNotIn('error', result)

    def test_collision_rejected_without_overriding(self):
        class Colliding(Context):
            def register_tool(self, **kw):
                if kw['name']=='bsv_inspect_transaction': return None
                return super().register_tool(**kw)
        with self.assertRaises(RuntimeError):
            adapter.register(Colliding())
