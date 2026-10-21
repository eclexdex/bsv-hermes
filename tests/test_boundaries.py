import copy
import json
import tracemalloc
import unittest
from unittest.mock import patch
from bsv_hermes import adapter
from bsv_hermes.kits.assurance import core as assurance
from bsv_hermes.kits.integrations import core as integrations
from test_unified import Context

class BoundaryTests(unittest.TestCase):
    def test_early_native_budget_before_nested_receipt_comparison(self):
        ctx = Context(['identity','assurance','integrations']); adapter.register(ctx)
        args={'data_b64':'YQ==','network':'testnet','receipt':{'unused':'\0'*2000000}}
        tracemalloc.start()
        result=json.loads(ctx.tools['bsv_identity_soul']['handler'](args))
        _, peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
        self.assertFalse(result['ok'])
        self.assertLess(peak, 100000)
        self.assertEqual(result['error']['code'], 'invalid_input')
        for bad in [None, [], True, '{bad json', {'unknown':'private-marker'}, {'x':float('nan')}]:
            for tool in ctx.tools.values():
                value=json.loads(tool['handler'](bad))
                self.assertFalse(value['ok'])
                self.assertNotIn('private-marker',json.dumps(value))
        deep={}; deep['loop']=deep
        self.assertFalse(json.loads(ctx.tools['bsv_identity_soul']['handler'](dict(args,receipt=deep)))['ok'])

    def test_schema_types_enforced_before_identity_comparison(self):
        handler=adapter.tool_specs()['bsv_identity_soul'][0]
        # Well-typed unmatched receipt is a comparison failure; non-object is an input error.
        base={'data_b64':'YQ==','network':'testnet'}
        invalid=json.loads(handler(dict(base,receipt=5)))
        self.assertFalse(invalid['ok'])
        valid=json.loads(handler(dict(base,receipt={})))
        self.assertTrue(valid['ok']); self.assertFalse(valid['result']['matches'])

class RefereeRegressions(unittest.TestCase):
    def test_f1_chain_receipt_types_bound(self):
        value={'network':'testnet','nonce':'a'*64,'events':[
            {'call_digest':'b'*64,'phase':'attempt','outcome':'pending'},
            {'call_digest':'b'*64,'phase':'terminal','outcome':'ok'}]}
        receipt=assurance.chain(value)
        self.assertTrue(assurance.verify_chain(receipt))
        for field,bad in [('version',True),('version',1.0),('pending_count',False),('pending_count',0.0)]:
            altered=copy.deepcopy(receipt); altered[field]=bad
            with self.subTest(field=field,value=repr(bad)):
                self.assertFalse(assurance.verify_chain(altered))

    def test_batch_private_default_no_proofs_and_explicit_export(self):
        args={'digests':['a'*64,'b'*64],'network':'testnet','nonce':'c'*64}
        handler=adapter.tool_specs(['integrations'])['bsv_int_batch'][0]
        default=json.loads(handler(args))
        self.assertTrue(default['ok']); self.assertNotIn('proofs', default['result'])
        self.assertEqual(default['result']['commitment'], integrations.batch(args)['commitment'])
        exported=json.loads(handler(dict(args,export_private_proofs=True)))
        self.assertTrue(exported['ok'])
        self.assertEqual(exported['result']['proofs'], integrations.batch(args)['proofs'])
        self.assertTrue(any('guess' in w.lower() for w in exported['warnings']))
        self.assertNotIn(args['nonce'],json.dumps(exported))
        self.assertFalse(json.loads(handler(dict(args,export_private_proofs=1)))['ok'])
