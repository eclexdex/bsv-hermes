"""Independent synthetic input construction, never chain/provider data."""
import hashlib
import json


def cases():
    def commit(kind,value):
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        return hashlib.sha256(b'hermes-assurance/v1\0'+kind.encode('ascii')+b'\0'+raw).hexdigest()
    artifact={'network':'testnet','items':[{'digest':'a'*64,'bytes':3}],'nonce':'b'*64}
    chain={'network':'testnet','events':[{'call_digest':'a'*64,'phase':'attempt','outcome':'pending'},{'call_digest':'a'*64,'phase':'terminal','outcome':'ok'}],'nonce':'c'*64}
    a={'version':1,'kind':'artifact','projection':artifact,'digest':commit('artifact',artifact)}
    links=[]; previous='0'*64
    for index,event in enumerate(chain['events']):
        previous=commit('tool-chain-link',{'previous':previous,'event':event,'index':index,'network':'testnet','nonce':'c'*64}); links.append(previous)
    c={'version':1,'kind':'tool-chain','projection':chain,'digest':commit('tool-chain',chain),'links':links,'head':previous,'pending_count':0}
    intent={'network':'testnet','action_digest':'a'*64,'nonce':'b'*64,'issued_at':100,'expires_at':200}
    ds=['a'*64]; nonce='33'*16
    leaf=hashlib.sha256(b'\0'+bytes(4)+bytes.fromhex(ds[0])).digest()
    header={'domain':'bsv-hermes/merkle-batch/v1','count':1,'root':leaf.hex(),'network':'testnet','nonce':nonce}
    batch=hashlib.sha256(b'\2'+json.dumps(header,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {
        'bsv_capabilities':{},
        'bsv_inspect_script':{'script_hex':'006a0141'},
        'bsv_inspect_transaction':{'transaction_hex':'0100000001'+'00'*32+'ffffffff00ffffffff01e803000000000000015100000000'},
        'bsv_plan_commitment':{'text':''},
        'bsv_identity_soul':{'data_b64':'c3ludGhldGlj','network':'testnet'},
        'bsv_assurance_artifact':{'evidence':artifact},
        'bsv_identity_instructions':{'entries':[{'path':'SKILL.md','data_b64':'YQ=='}],'network':'testnet'},
        'bsv_identity_release':{'entries':[{'path':'plugin.yaml','data_b64':'YQ=='}],'network':'testnet'},
        'bsv_identity_posture':{'fields':{'hermes_version':'0.9.0','approval_mode':'required','network_access':'disabled','max_iterations':10,'telemetry_enabled':False},'network':'testnet'},
        'bsv_assurance_tool_chain':{'evidence':chain},
        'bsv_assurance_deployment_gate':{'evidence':{'network':'testnet','artifact':a,'chain':c,'required_digests':['a'*64],'max_age':30,'observed_at':100,'now':110}},
        'bsv_assurance_approval_intent':{'evidence':{'intent':intent,'token':{'intent_digest':commit('approval-intent',intent),'nonce':'b'*64},'now':150,'used_nonces':[]}},
        'bsv_int_batch':{'digests':ds,'network':'testnet','nonce':nonce},
        'bsv_int_verify_batch':{'digest':ds[0],'proof':{'domain':'bsv-hermes/merkle-batch/v1','network':'testnet','count':1,'index':0,'siblings':[]},'commitment':batch,'network':'testnet','nonce':nonce},
        'bsv_int_content':{'network':'testnet','content_hex':'616263','expected_sha256':'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'},
        'bsv_int_overlay':{'network':'testnet','service':'fixture','provider':'fixture','query_digest':'a'*64,'result_digest':'b'*64,'observed_at':100,'nonce':nonce},
        'bsv_int_handoff':{'network':'testnet','task_id':'task','parent':'parent','child':'child','goal_digest':'a'*64,'artifact_digests':['b'*64],'previous_digest':'0'*64,'sequence':1,'issued_at':100,'expires_at':200,'now':150,'nonce':nonce,'seen':[]},
        'bsv_int_chain':{'network':'testnet','raw_hex':'00','expected_txid':hashlib.sha256(hashlib.sha256(b'\0').digest()).digest()[::-1].hex()},
        'bsv_int_reconcile':{'network':'testnet','expected_digest':'a'*64,'expected_txid':'b'*64,'receipt':{}}
    }
