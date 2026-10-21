"""Native facade adapter; deliberately registers no lifecycle hooks."""
from . import core
from .contracts import SCHEMAS
import json

def native_handler(operation):
    def run(args, **kwargs):
        return json.dumps(handler(operation)(args, **kwargs), sort_keys=True)
    return run

OPERATIONS={'artifact':core.artifact,'tool_chain':core.chain,'deployment_gate':core.gate,'approval_intent':core.approval}

def handler(operation):
    def run(args, **kwargs):
        try:
            core.fields(args, ('evidence',))
            result=OPERATIONS[operation](args['evidence'])
            # Never return input projections or local privacy nonces.
            if operation in ('artifact','tool_chain'):
                result={k:v for k,v in result.items() if k not in ('projection','links')}
            if operation=='approval_intent': result.pop('nonce_to_record',None)
            return {'ok':True,'data':result,'warnings':['Offline supplied evidence only; not execution truth, consent, or chain finality.']}
        except (core.Invalid, KeyError, TypeError, ValueError, RecursionError):
            return {'ok':False,'error':{'code':'invalid_evidence'}}
    return run
