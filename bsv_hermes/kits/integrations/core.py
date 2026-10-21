"""Original stdlib offline evidence protocols, not BEEF/SPV verification."""
import hashlib
import json
import re

MAX_BYTES = 65536
DOMAIN = 'bsv-hermes/merkle-batch/v1'

def canonical(value):
    # Count the exact ASCII JSON size before allocating serialized bytes.
    used=0;nodes=0
    def add(n):
        nonlocal used
        used+=n
        if used>MAX_BYTES:raise ValueError('byte limit')
    def string(v):
        if len(v)>MAX_BYTES:raise ValueError('string limit')
        add(2)
        for c in v:
            cp=ord(c)
            add(2 if c in '\"\\\\\b\f\n\r\t' else 6 if cp<32 or 127<=cp<=65535 else 12 if cp>65535 else 1)
    def check(v, depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>4096:raise ValueError('node limit')
        if depth>12:raise ValueError('depth limit')
        if v is None:add(4);return
        if type(v) is bool:add(4 if v else 5);return
        if type(v) is str:string(v);return
        if type(v) is int and abs(v)<=9007199254740991:add(len(str(v)));return
        if type(v) is list and len(v)<=1024:
            add(2+max(0,len(v)-1))
            for x in v:check(x,depth+1)
            return
        if type(v) is dict and len(v)<=64:
            add(2+max(0,len(v)-1)+len(v))
            for k,x in v.items():
                if type(k) is not str:raise ValueError('key type')
                nodes+=1
                if nodes>4096:raise ValueError('node limit')
                string(k);check(x,depth+1)
            return
        raise ValueError('unsupported canonical value')
    check(value)
    data=json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(data)>MAX_BYTES:raise ValueError('byte limit')
    return data

def sha(data): return hashlib.sha256(data).digest()
def digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None: raise ValueError('expected lowercase 32-byte digest')
    return bytes.fromhex(value)
def network(value):
    if value not in ('mainnet','testnet'): raise ValueError('explicit network required')
    return value

def token(value):
    if type(value) is not str or re.fullmatch('[A-Za-z0-9_.:-]{1,80}',value) is None: raise ValueError('invalid identifier')
    return value

def commitment(root,count,net,nonce):
    if type(nonce) is not str or re.fullmatch('(?:[0-9a-f]{2}){16,64}',nonce) is None: raise ValueError('local privacy nonce required: 16-64 bytes hex')
    return sha(b'\x02'+canonical({'domain':DOMAIN,'count':count,'root':root.hex(),'network':network(net),'nonce':nonce})).hex()

def batch(a):
    canonical(a)
    ds=a['digests'];net=network(a['network']);nonce=a.get('nonce','')
    if type(ds) is not list or not 1<=len(ds)<=256: raise ValueError('1-256 digests required')
    leaves=[sha(b'\x00'+i.to_bytes(4,'big')+digest(d)) for i,d in enumerate(ds)]
    levels=[leaves]
    while len(levels[-1])>1:
        row=levels[-1];levels.append([sha(b'\x01'+row[i]+row[min(i+1,len(row)-1)]) for i in range(0,len(row),2)])
    proofs=[]
    for i in range(len(ds)):
        idx=i;path=[]
        for row in levels[:-1]:
            path.append(row[idx^1 if idx^1<len(row) else idx].hex());idx//=2
        proofs.append({'domain':DOMAIN,'network':net,'count':len(ds),'index':i,'siblings':path})
    return {'version':1,'commitment':commitment(levels[-1][0],len(ds),net,nonce),'count':len(ds),'proofs':proofs,'publication':'unsigned-plan-only','nonce_retention':'caller retains nonce locally; do not publish receipts automatically'}

def bounded_hex(value):
    if type(value) is not str or len(value)>MAX_BYTES or len(value)%2 or re.fullmatch('[0-9a-f]*',value) is None:raise ValueError('bounded lowercase hex required')
    return bytes.fromhex(value)

def content(a):
    canonical(a);network(a['network']);raw=bounded_hex(a['content_hex']);expected=digest(a['expected_sha256']);actual=sha(raw)
    return {'version':1,'digest_match':actual==expected,'sha256':actual.hex(),'byte_count':len(raw),'resolution':'not-performed','uhrp_url_decoding':'not-implemented; caller supplies expected SHA256','advertisement_validation':'unchecked','availability':'unknown','safety':'unchecked'}

def integer(v, low=0, high=9007199254740991):
    if type(v) is not int or not low<=v<=high:raise ValueError('integer out of range')
    return v

def envelope_receipt(envelope, receipt=None):
    h=sha(b'bsv-hermes/evidence-envelope/v1\x00'+canonical(envelope)).hex()
    public_envelope={k:v for k,v in envelope.items() if k != 'nonce'}
    result={'envelope':public_envelope,'digest':h,'authentication':'none; digest integrity only'}
    if receipt is not None:
        result['integrity_match']=canonical(receipt)==canonical(result)
    return result

def overlay(a):
    canonical(a)
    e={'domain':'bsv-hermes/overlay-provenance/v1','network':network(a['network']),'service':token(a['service']),'provider':token(a['provider']),'query_digest':digest(a['query_digest']).hex(),'result_digest':digest(a['result_digest']).hex(),'observed_at':integer(a['observed_at']),'nonce':a['nonce']}
    commitment(bytes(32),1,a['network'],a['nonce'])
    result=dict(envelope_receipt(e),result_truth='unchecked',provider_identity='untrusted caller label',observation_time='caller claim; not chain timestamp',overlay_consensus='unchecked')
    if 'receipt' in a: result['integrity_match']=canonical(a['receipt'])==canonical(result)
    return result

def handoff(a):
    canonical(a);net=network(a['network']);commitment(bytes(32),1,net,a['nonce'])
    issued=integer(a['issued_at']);expires=integer(a['expires_at']);now=integer(a['now'])
    if expires<=issued:raise ValueError('expiry must follow issue time')
    artifacts=a['artifact_digests'];seen=a['seen']
    if type(artifacts) is not list or len(artifacts)>256 or type(seen) is not list or len(seen)>256:raise ValueError('digest list limit')
    for d in artifacts+seen:digest(d)
    e={'domain':'bsv-hermes/delegation-handoff/v1','network':net,'task_id':token(a['task_id']),'parent':token(a['parent']),'child':token(a['child']),'goal_digest':digest(a['goal_digest']).hex(),'artifact_digests':artifacts,'previous_digest':digest(a['previous_digest']).hex(),'sequence':integer(a['sequence'],1),'issued_at':issued,'expires_at':expires,'nonce':a['nonce']}
    r=envelope_receipt(e);fresh=issued<=now<expires;replay=r['digest'] in seen
    result=dict(r,fresh_at_supplied_time=fresh,replay_in_supplied_history=replay,acceptable_integrity_evidence=fresh and not replay,peer_authentication='unchecked',authorization='unchecked',artifact_bytes='not-read; caller must independently hash artifacts',replay_store='caller supplied, completeness unchecked')
    if 'receipt' in a:
        result['integrity_match']=canonical(a['receipt'])==canonical(result)
        result['acceptable_integrity_evidence'] &= result['integrity_match']
    return result

def chain(a):
    canonical(a);network(a['network'])
    if a.get('format','raw')!='raw':raise ValueError('only raw byte hashing supported; no BEEF/BUMP parsing')
    raw=bounded_hex(a['raw_hex']);expected=digest(a['expected_txid'])
    if not raw:raise ValueError('nonempty bytes required')
    h=lambda b:sha(sha(b))
    leaf=h(raw);branch=None;header_match=None;root=None
    if 'proof' in a:
        p=a['proof'];n=integer(p['count'],1,2**32);i=integer(p['index'],0,n-1);node=leaf;k=0
        siblings=p['siblings']
        if type(siblings) is not list or len(siblings)>32:raise ValueError('branch depth limit')
        while n>1:
            if k>=len(siblings):raise ValueError('missing sibling')
            other=digest(siblings[k])[::-1];k+=1
            if i%2==0 and i+1==n and other!=node:raise ValueError('odd row requires duplicate sibling')
            node=h(other+node if i%2 else node+other);i//=2;n=(n+1)//2
        if k!=len(siblings):raise ValueError('extra siblings')
        root=digest(p['root'])[::-1];branch=node==root
    header_hash=None
    if 'header_hex' in a:
        header=bounded_hex(a['header_hex'])
        if len(header)!=80:raise ValueError('80-byte header required')
        header_hash=h(header)[::-1].hex()
        if root is not None:header_match=header[36:68]==root
    return {'version':1,'raw_bytes_txid':leaf[::-1].hex(),'raw_bytes_txid_match':leaf[::-1]==expected,'branch_root_match':branch,'header_root_match':header_match,'header_hash':header_hash,'transaction_structure':'unchecked','scripts':'unchecked','inclusion':'arithmetic comparison only; supplied root/header untrusted','header_pow':'unchecked','header_chain':'unchecked','network_binding':'caller label only; not established by bytes','proof_leaf_count':'caller supplied; Bitcoin Merkle root does not bind count','freshness':'unknown','spend_status':'unknown','beef_bump':'unsupported','spv_verified':False}

def reconcile(a):
    canonical(a);network(a['network']);digest(a['expected_digest']);digest(a['expected_txid']);r=a['receipt']
    if type(r) is not dict:raise ValueError('receipt object required')
    def match(field, expected):
        if field not in r:return None
        digest(r[field]);return r[field]==expected
    matches={'network_match':r.get('network')==a['network'] if 'network' in r else None,'domain_match':r.get('domain')==a.get('expected_domain',DOMAIN) if 'domain' in r else None,'digest_match':match('digest',a['expected_digest']),'txid_claim_match':match('txid',a['expected_txid'])}
    return dict(matches,receipt_claim='untrusted-caller-supplied',receipt_claims_match=all(v is True for v in matches.values()),inclusion='unchecked',chain_validation='unchecked',timestamp='untrusted claim; not legal attestation',verified_anchor=False)

def verify_batch(a):
    try:
        canonical(a);p=a['proof'];n=p['count'];i=p['index']
        if p['domain']!=DOMAIN or p['network']!=network(a['network']) or type(n) is not int or not 1<=n<=256 or type(i) is not int or not 0<=i<n:return False
        node=sha(b'\x00'+i.to_bytes(4,'big')+digest(a['digest']))
        siblings=p['siblings'];k=0
        while n>1:
            other=digest(siblings[k]);k+=1
            if i%2==0 and i+1==n and other!=node:return False
            node=sha(b'\x01'+(other+node if i%2 else node+other));n=(n+1)//2;i//=2
        return k==len(siblings) and commitment(node,p['count'],a['network'],a['nonce'])==a['commitment']
    except (KeyError,ValueError,TypeError,IndexError,OverflowError):return False
