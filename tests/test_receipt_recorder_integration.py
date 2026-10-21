import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from test_receipt_integration import request


class RecorderIntegration(unittest.TestCase):
    def test_unarmed_allowlist_recording_as_explicit_input(self):
        self.assertIsNotNone(importlib.util.find_spec('bsv_hermes.receipts.recorder'), 'recorder missing')
        from bsv_hermes.receipts import gateway_adapter as hook, producer, evidence
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'events.jsonl'
            hook.disarm()
            hook.handle('agent:start', {'session_id': 'synthetic'})
            self.assertFalse(path.exists())
            rec = hook.arm(path, consent=True, session_id='synthetic', events=['agent:start','agent:end'])
            try:
                canary = 'SYNTHETIC_SECRET_NOT_A_CREDENTIAL'
                hook.handle('agent:start', {'session_id':'other', 'message':canary})
                hook.handle('agent:start', {'session_id':'synthetic', 'message':canary, 'api_key':canary, 'iteration':5})
                hook.handle('agent:end', {'session_id':'synthetic', 'response':canary})
            finally:
                hook.disarm()
            raw = path.read_bytes()
            self.assertNotIn(canary.encode(), raw)
            self.assertEqual([x['fields'] for x in map(json.loads, raw.splitlines())], [{}, {}])
            self.assertFalse(rec.result()['complete_trace'])
            req = request(); req['approved_inputs'] = [{'id':'lifecycle', 'bytes_b64':base64.b64encode(raw).decode()}]
            bundle = producer.build_run(req)['bundle']
            report = evidence.verify(bundle, {'lifecycle':path})
            item = next(x for x in report['results']['artifact']['items'] if x['id']=='lifecycle')
            self.assertEqual(item['status'], 'match')
            self.assertEqual(report['source_authentication']['status'], 'unchecked')
            self.assertEqual(bundle['tools'], [])
