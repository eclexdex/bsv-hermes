"""Actual gateway HookRegistry acceptance; synthetic isolated HOME, no live activation.

Run with the host interpreter and host source on PYTHONPATH. Uses only documented
discovery/emit. This is not a model run or a complete tool-execution trace.
"""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch


def main():
    source = Path(sys.argv[1] if len(sys.argv)>1 else Path(__file__).resolve().parents[1]).resolve()
    sys.path.insert(0, str(source))
    with tempfile.TemporaryDirectory(prefix='receipt-hook-') as temp:
        home = Path(temp)
        os.environ['HOME'] = os.environ['HERMES_HOME'] = str(home)
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden')):
            from gateway.hooks import HookRegistry
            import gateway.hooks as hooks
            from bsv_hermes.receipts import gateway_adapter as adapter, producer, evidence, recorder
            assert Path(recorder.__file__).resolve().is_relative_to(source)
            hooks.HOOKS_DIR = home/'hooks'
            hook = hooks.HOOKS_DIR/'receipt-synthetic'
            hook.mkdir(parents=True)
            (hook/'HOOK.yaml').write_text('name: receipt-synthetic\ndescription: Isolated synthetic test only\nevents:\n  - agent:start\n  - agent:step\n  - agent:end\n')
            (hook/'handler.py').write_text('from bsv_hermes.receipts.gateway_adapter import handle\n')
            registry = HookRegistry(); registry.discover_and_load()
            assert len(registry.loaded_hooks) == 1
            output = home/'events.jsonl'
            asyncio.run(registry.emit('agent:start', {'session_id':'synthetic'}))
            assert not output.exists()
            adapter.arm(output, consent=True, session_id='synthetic', events=['agent:start','agent:step','agent:end'], fields=['iteration'])
            canary = 'SYNTHETIC_NEVERFUNDED_CANARY_EXCLUDED'
            try:
                for i, event in enumerate(('agent:start','agent:step','agent:end')):
                    asyncio.run(registry.emit(event, {'session_id':'synthetic', 'iteration':i, 'message':canary,
                        'response':canary, 'tool_names':[canary], 'args':{'password':canary}, 'result':canary, 'api_key':canary}))
            finally:
                adapter.disarm()
            raw = output.read_bytes()
            assert canary.encode() not in raw and b'synthetic' not in raw
            rows = [json.loads(x) for x in raw.splitlines()]
            assert [r['event'] for r in rows] == ['agent:start','agent:step','agent:end']
            previous = '0'*64
            for index,row in enumerate(rows):
                assert row['previous'] == previous and row['index'] == index
                body = {k:v for k,v in row.items() if k != 'event_digest'}
                previous = hashlib.sha256(b'hermes-recorder/v1\x00'+json.dumps(body, sort_keys=True, separators=(',',':'), ensure_ascii=True).encode()).hexdigest()
                assert previous == row['event_digest'] and row['fields'] == {'iteration':index}
            part = lambda name, data: {'id':name, 'bytes_b64':base64.b64encode(data).decode()}
            bundle = producer.build_run({'run_id':'synthetic', 'instruction':part('instruction',b'abc'),
                'approved_inputs':[part('lifecycle',raw)], 'tools':[], 'final_output':part('output',b'')})['bundle']
            report = evidence.verify(bundle, {'lifecycle':output})
            assert report['results']['chain']['status'] == 'match'
            assert next(x for x in report['results']['artifact']['items'] if x['id']=='lifecycle')['status'] == 'match'
            assert report['source_authentication']['status'] == 'unchecked'
            print(json.dumps({'host_api':'actual HookRegistry.discover_and_load + emit', 'unarmed_no_write':True,
                'canary_absent':True,'events':len(rows),'receipt_report':report,'live_activation':False}, sort_keys=True))


if __name__ == '__main__':
    main()
