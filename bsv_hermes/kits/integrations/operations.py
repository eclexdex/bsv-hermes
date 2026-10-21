"""Hermes facade adapter. Registration does not read configuration or attach hooks."""
import json
import re
from . import core

D={'type':'string','pattern':'^[0-9a-f]{64}$'}
N={'type':'string','enum':['mainnet','testnet']}
T={'type':'string','pattern':'^[A-Za-z0-9_.:-]{1,80}$'}
NONCE={'type':'string','pattern':'^(?:[0-9a-f]{2}){16,64}$'}
I={'type':'integer','minimum':0,'maximum':9007199254740991}
HEX={'type':'string','pattern':'^(?:[0-9a-f]{2})*$','maxLength':60000}

def obj(properties,required=None):
    return {'type':'object','properties':properties,'required':list(properties) if required is None else required,'additionalProperties':False}
def arr(item,maximum=256,minimum=0):return {'type':'array','items':item,'minItems':minimum,'maxItems':maximum}
PROOF=obj({'domain':{'type':'string','enum':[core.DOMAIN]},'network':N,'count':{'type':'integer','minimum':1,'maximum':256},'index':I,'siblings':arr(D,8)})
RECEIPT=obj({'envelope':{'type':'object'},'digest':D,'authentication':{'type':'string'},'result_truth':{'type':'string'},'provider_identity':{'type':'string'},'observation_time':{'type':'string'},'overlay_consensus':{'type':'string'},'fresh_at_supplied_time':{'type':'boolean'},'replay_in_supplied_history':{'type':'boolean'},'acceptable_integrity_evidence':{'type':'boolean'},'peer_authentication':{'type':'string'},'authorization':{'type':'string'},'artifact_bytes':{'type':'string'},'replay_store':{'type':'string'}},['envelope','digest'])
PARAMETERS={
'batch':obj({'digests':arr(D,256,1),'network':N,'nonce':NONCE}),
'verify_batch':obj({'digest':D,'proof':PROOF,'commitment':D,'network':N,'nonce':NONCE}),
'reconcile':obj({'network':N,'expected_domain':{'type':'string','pattern':'^[A-Za-z0-9_./:-]{1,120}$'},'expected_digest':D,'expected_txid':D,'receipt':obj({'network':N,'domain':{'type':'string','pattern':'^[A-Za-z0-9_./:-]{1,120}$'},'digest':D,'txid':D,'included':{'type':'boolean'},'chain_validated':{'type':'boolean'},'timestamp':I},[])},['network','expected_digest','expected_txid','receipt']),
'content':obj({'network':N,'content_hex':HEX,'expected_sha256':D}),
'overlay':obj({'network':N,'service':T,'provider':T,'query_digest':D,'result_digest':D,'observed_at':I,'nonce':NONCE,'receipt':RECEIPT},['network','service','provider','query_digest','result_digest','observed_at','nonce']),
'handoff':obj({'network':N,'task_id':T,'parent':T,'child':T,'goal_digest':D,'artifact_digests':arr(D),'previous_digest':D,'sequence':{'type':'integer','minimum':1,'maximum':9007199254740991},'issued_at':I,'expires_at':I,'now':I,'nonce':NONCE,'seen':arr(D),'receipt':RECEIPT},['network','task_id','parent','child','goal_digest','artifact_digests','previous_digest','sequence','issued_at','expires_at','now','nonce','seen']),
'chain':obj({'network':N,'format':{'type':'string','enum':['raw']},'raw_hex':HEX,'expected_txid':D,'proof':obj({'count':{'type':'integer','minimum':1,'maximum':4294967296},'index':I,'siblings':arr(D,32),'root':D}),'header_hex':{'type':'string','pattern':'^[0-9a-f]{160}$'}},['network','raw_hex','expected_txid'])}
DESCRIPTIONS={
'batch':'Create domain-separated ordered Merkle batch and unsigned commitment plan; nonce stays local.',
'verify_batch':'Verify offline positional batch membership, leaf count and network/domain binding.',
'reconcile':'Compare untrusted receipt digest/txid claims; never proves inclusion or chain validity.',
'content':'Hash supplied bytes against supplied SHA256 for UHRP workflows; no resolver/download.',
'overlay':'Create/check supplied query/result digest provenance; no overlay query or result truth.',
'handoff':'Create/check delegation digest envelope, expiry and supplied replay history; no peer auth.',
'chain':'Hash supplied raw bytes and compare Bitcoin branch/header roots; no tx parsing, BEEF or SPV.'}
SCHEMAS={k:{'name':'bsv_int_'+k,'description':DESCRIPTIONS[k],'parameters':p} for k,p in PARAMETERS.items()}

def validate(value,schema):
    typ=schema.get('type')
    types={'object':dict,'array':list,'string':str,'integer':int,'boolean':bool}
    if typ and type(value) is not types[typ]:raise ValueError('type')
    if 'enum' in schema and value not in schema['enum']:raise ValueError('enum')
    if typ=='object':
        props=schema.get('properties',{})
        if any(k not in value for k in schema.get('required',[])):raise ValueError('missing')
        if schema.get('additionalProperties') is False and any(k not in props for k in value):raise ValueError('unknown')
        for k,v in value.items():
            if k in props:validate(v,props[k])
    if typ=='array':
        if not schema.get('minItems',0)<=len(value)<=schema.get('maxItems',1024):raise ValueError('count')
        for x in value:validate(x,schema['items'])
    if typ=='string':
        if len(value)>schema.get('maxLength',65536):raise ValueError('length')
        if 'pattern' in schema and re.fullmatch(schema['pattern'],value) is None:raise ValueError('pattern')
    if typ=='integer' and not schema.get('minimum',-9007199254740991)<=value<=schema.get('maximum',9007199254740991):raise ValueError('range')

def dispatch(action,args):
    try:
        if action not in PARAMETERS:raise ValueError('action')
        core.canonical(args);validate(args,PARAMETERS[action])
        data=getattr(core,action)(args)
        return {'ok':True,'version':1,'data':data,'warnings':['Offline caller-supplied evidence only. No authorship, publication, finality or authorization inferred.'],'provenance':{'implementation':'bsv-integrations/0.1.0','network_access':False,'canonicalization':'json-ascii-sorted-no-floats/v1'}}
    except (ValueError,KeyError,TypeError,IndexError,RecursionError,OverflowError):
        return {'ok':False,'version':1,'data':None,'error':{'code':'INVALID_INPUT','message':'Input rejected; review bounded schema. Values are not echoed.'}}
