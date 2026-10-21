import json
import unittest
from bsv_hermes import adapter


NAMES = {'bsv_wallet_address', 'bsv_funding_status', 'bsv_publish_prepare', 'bsv_publish_sign',
         'bsv_publish_submit', 'bsv_publish_status', 'bsv_publish_receipt', 'bsv_spend_policy_status'}


class MainnetNative(unittest.TestCase):
    def test_enabled_capabilities_distinguish_configuration_from_authorization(self):
        class Context:
            def __init__(self):
                self.tools = {}
            def get_config(self, key, default=None):
                return ['mainnet'] if key == 'enabled_kits' else default
            def register_tool(self, **kwargs):
                self.tools[kwargs['name']] = kwargs['handler']
                return object()
            def register_skill(self, *args, **kwargs):
                return object()
        ctx = Context(); adapter.register(ctx)
        caps = json.loads(ctx.tools['bsv_capabilities']({}))['result']
        self.assertTrue(caps['network'])
        self.assertTrue(caps['signing'])
        self.assertFalse(caps['payments'])
        self.assertFalse(caps['mainnet']['configured'])
        self.assertFalse(caps['mainnet']['ready_for_mainnet'])

    def test_one_opt_in_surface_and_unconfigured_is_not_synthetic_success(self):
        defaults = adapter.tool_specs()
        specs = adapter.tool_specs(['mainnet'])
        self.assertEqual(len(defaults), 6)
        self.assertEqual(set(specs) - set(defaults), NAMES)
        for name in NAMES:
            handler, schema = specs[name]
            args = {'workflow_id': 'fixture'} if 'workflow_id' in schema['parameters']['required'] else {}
            if name == 'bsv_publish_prepare':
                args['text'] = 'public fixture'
            result = json.loads(handler(args))
            self.assertFalse(result['ok'])
            self.assertEqual(result['error']['code'], 'mainnet_not_configured')
            for field in ('approved', 'approval', 'session_id', 'path', 'python', 'network', 'max_cost_sat'):
                denied = json.loads(handler(dict(args, **{field: 'CANARY'})))
                self.assertEqual(denied['error']['code'], 'invalid_input')
                self.assertNotIn('CANARY', json.dumps(denied))
