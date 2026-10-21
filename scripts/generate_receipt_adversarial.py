"""Explicit maintenance only: translate lane10 semantics, NEVER its hash domains.

Generate production-format fixtures from independently supplied lane01 literal
bytes. Expected statuses are hand-authored here, not calculated by a verifier.
Tests consume the frozen JSON + SHA256 and never execute this generator.
"""
from pathlib import Path
import copy, hashlib, json

ROOT=Path(__file__).resolve().parents[1]
F=ROOT/'tests/receipt_vectors'
G=json.loads((F/'contract/golden.json').read_text())
A=json.loads((F/'contract/artifacts.json').read_text())
C=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
H=lambda x:hashlib.sha256(x).hexdigest()
DOMAIN='bsv-hermes-receipt-batch/1'
TAG=lambda tag,x:H((DOMAIN+'/'+tag+'\0').encode()+C(x))
leaf={'receipt_id':'literal','receipt_sha256':H(C(G)),'nonce_hex':'01'*32}
root=TAG('leaf',leaf)
commitment=TAG('commitment',{'root':root,'count':1,'network':'mainnet'})
proof=dict(leaf,version=DOMAIN,index=0,count=1,network='mainnet',siblings=[])
BASE={'parse':'match','artifact':'match','chain':'match','signature':'missing','batch':'missing','inclusion':'missing','publication':'missing','source':'unverified'}
BAD={**{k:'missing' for k in BASE},'parse':'mismatch','source':'unverified'}
cases=[]
def add(name,b=None,expected=None,artifacts=None,**trust):
    req={'bundle':(b if isinstance(b,str) else C(G if b is None else b).decode()),'artifacts_hex':A if artifacts is None else artifacts,**trust}
    cases.append({'id':name,'request':req,'expected':dict(BASE,**(expected or {}))})
def changed(fn):
    b=copy.deepcopy(G);fn(b);return b
add('baseline')
a=dict(A);a['final-output']='00'; output_name=G['final_output']['name'];a=dict(A);a[output_name]='00'
add('artifact-tamper',artifacts=a,expected={'artifact':'mismatch'})
add('artifact-ungranted',artifacts={},expected={'artifact':'unchecked'})
for name,value in [('bool-count',True),('float-count',2.0),('negative-count',-1),('huge-count',16777217)]:
    add(name,changed(lambda b:b['instruction'].__setitem__('size',value)),BAD)
add('bool-index',changed(lambda b:b['tools'][0].__setitem__('index',False)),BAD)
add('duplicate-key','{"version":"hermes-receipt/v1",'+C(G).decode()[1:],BAD)
for name,value in [('nan','NaN'),('infinity','Infinity')]:
    add(name,'{"x":'+value+'}',BAD)
add('tool-reorder',changed(lambda b:b['tools'].reverse()),{'chain':'mismatch'})
b=copy.deepcopy(G); removed=b['tools'].pop(); a={k:v for k,v in A.items() if k not in (removed['request']['name'],removed['response']['name'])}
add('tool-truncate',b,{'chain':'mismatch'},a)
add('instruction-tamper',changed(lambda b:b['instruction'].__setitem__('sha256','00'*32)),{'chain':'mismatch','artifact':'mismatch'})
def env(**kw):return dict(adapter='bsv-hermes/receipt-evidence/v2',bundle=G,**kw)
add('unsigned-bundled-key',env(signature={'key':'untrusted','value':'not a signature'}),{'signature':'unchecked'})
for name in ('key-substitution','matching-key-not-valid-signature'):
    add(name,env(signature={'key':'untrusted','value':'not a signature'}),{'signature':'mismatch'},trusted_key='00'*32,now=150)
add('batch-root-mismatch',env(batch=proof),{'batch':'mismatch'},batch_commitment='00'*32)
add('batch-single-leaf',env(batch=proof),{'batch':'match'},batch_commitment=commitment)
add('batch-root-not-specified',env(batch=proof),{'batch':'unchecked'})
add('batch-invalid-side',env(batch=dict(proof,side='left')),{'batch':'mismatch'},batch_commitment=commitment)
add('provider-inclusion-lie',env(inclusion={'version':'bsv-hermes/publication-evidence/v1','provider_report':{'included':True}}),{'publication':'unchecked'})
add('chain-digest-missing',changed(lambda b:b.pop('receipt_digest')),BAD)
# Preserve wire-level parser attacks from frozen lane10 without JSON rewriting.
original=json.loads((F/'adversarial-original.json').read_text())
for case in original['cases']:
    if case['id'] in ('empty-bundle','oversize-bundle','deep-json','oversize-tools'):
        add('original-wire-'+case['id'],case['request']['bundle'],BAD)
# Product-specific bounds (original oversized cases use a different, smaller cap).
add('production-byte-budget',' '*(1048576+1),BAD)
add('production-depth-budget','['*26+'0'+']'*26,BAD)
add('nested-duplicate',C(G).decode().replace('"size":','"size":0,"size":',1),BAD)
path=F/'adversarial-production.json'
if path.exists(): raise SystemExit('refuse fixture regeneration; review a new version')
raw=(json.dumps({'format':'production-adversarial/v1','source_vector_sha256':H((F/'adversarial-original.json').read_bytes()),'mapping':'Explicit semantic cases; no digest reinterpretation. Product statuses differ for malformed/missing evidence. ZIP importer not supported.','cases':cases},indent=2)+'\n').encode()
path.write_bytes(raw);path.with_suffix('.sha256').write_text(H(raw)+'\n')
print(json.dumps({'cases':len(cases),'sha256':H(raw)}))
