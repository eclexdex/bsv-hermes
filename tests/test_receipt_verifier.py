import builtins
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from bsv_hermes.receipts import verifier as v

HERE = Path(__file__).resolve().parent
LITERAL = json.loads((HERE / 'receipt_vectors/verifier/literal.json').read_text())
RECEIPT = '65c3c653b6d636a7af184a931754359ada7210fc29041bd7e7147b6ec07e1fbf'
ROOT = '230fc5d0cba21e139c71313669310d965f77683fab71410a727acd92e9a35e0a'
PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
SIG = 'a03a1d1eadda0837e373bda69a45657c690c2bab0cdc6cd2a99c9c9c808fc34da569d97fbbb2cfa50bfe72e5d59f40e89b0fcbcb12798330461478d6c4b2f308'
RAW = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01000000000000000005006a02616200000000'
TXID = '1e0a68c15578ff32007938f83deb06a04dce27f5c11dea2e8b3cd5d153e8d271'
HEADER = '01000000000000000000000000000000000000000000000000000000000000000000000071d2e853d1d53c8b2eea1dc1f527ce4da006eb3df838790032ff7855c1680a1e000000000000000000000000'
ANCHOR = 'f47a031ebf162a7dac6b7a524607c379a9ff3afe53a6a84a83067e1cc996ec91'

def envelope(**sidecars):
    return dict(adapter='hermes-receipt/v1-external-v1', bundle=copy.deepcopy(LITERAL), **sidecars)

def inclusion():
    return dict(rawtx=RAW, txid=TXID, header=HEADER, index=0, siblings=[])

def independent_h(label, value):
    # Test-side canonical implementation, not imported verifier helpers.
    preimage = ('hermes-receipt/v1/' + label).encode() + b'\0' + json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(preimage).hexdigest()

def with_tools():
    b = copy.deepcopy(LITERAL)
    previous = independent_h('start', {k:b[k] for k in ('instruction', 'approved_inputs')})
    for i in range(2):
        req = dict(name='request'+str(i), sha256=LITERAL['instruction']['sha256'], size=0)
        res = dict(name='response'+str(i), sha256=LITERAL['instruction']['sha256'], size=0)
        event = dict(index=i, tool='synthetic', request=req, response=res, previous=previous)
        event['event_digest'] = independent_h('tool', event)
        b['tools'].append(event); previous = event['event_digest']
    b['receipt_digest'] = independent_h('bundle', {k:x for k,x in b.items() if k != 'receipt_digest'})
    return b

class VerifierTests(unittest.TestCase):
    def test_literal_oracle(self):
        r = v.verify(LITERAL)
        self.assertEqual(r['receipt_digest'], RECEIPT)
        self.assertEqual(r['evidence_chain']['status'], 'match')
        self.assertNotIn('verified', r)
        self.assertEqual(r['source_authentication']['status'], 'unchecked')

    def test_artifact_bytes(self):
        r = v.verify(LITERAL, {'instruction': HERE/'receipt_vectors/verifier/instruction.txt', 'output': HERE/'receipt_vectors/verifier/output.txt'})
        self.assertEqual([a['status'] for a in r['artifact_bytes']], ['match', 'match'])

    def test_artifact_tamper(self):
        r = v.verify(LITERAL, {'output': HERE/'receipt_vectors/verifier/instruction.txt'})
        self.assertEqual(r['artifact_bytes'][1]['status'], 'mismatch')
        self.assertEqual(r['evidence_chain']['status'], 'match')

    def test_no_implicit_reads(self):
        with patch.object(v, 'read_regular', side_effect=AssertionError('implicit read')):
            r = v.verify(LITERAL)
        self.assertTrue(all(a['status'] == 'unchecked' for a in r['artifact_bytes']))

    def test_missing_file(self):
        self.assertEqual(v.verify(LITERAL, {'output': HERE/'receipt_vectors/verifier/nonexistent'})['artifact_bytes'][1]['status'], 'missing')

    def test_unknown_grant(self):
        with self.assertRaises(v.Invalid):
            v.verify(LITERAL, {'unknown': '/never/read'})

    def test_symlinks(self):
        with tempfile.TemporaryDirectory(dir=HERE) as root:
            root = Path(root); (root/'link').symlink_to(HERE/'receipt_vectors/verifier/output.txt')
            self.assertEqual(v.verify(LITERAL, {'output': root/'link'})['artifact_bytes'][1]['status'], 'mismatch')
            (root/'dirlink').symlink_to(HERE/'receipt_vectors/verifier', target_is_directory=True)
            self.assertEqual(v.verify(LITERAL, {'output': root/'dirlink/output.txt'})['artifact_bytes'][1]['status'], 'mismatch')

    def test_directory_and_fifo_rejected(self):
        with tempfile.TemporaryDirectory(dir=HERE) as root:
            root = Path(root); os.mkfifo(root/'fifo')
            for p in (root, root/'fifo'):
                self.assertEqual(v.verify(LITERAL, {'output': p})['artifact_bytes'][1]['status'], 'mismatch')

    def test_oversize_file(self):
        with tempfile.TemporaryDirectory(dir=HERE) as root:
            p = Path(root)/'big'
            with p.open('wb') as f:
                f.truncate(v.MAX_ARTIFACT+1)
            self.assertEqual(v.verify(LITERAL, {'output': p})['artifact_bytes'][1]['status'], 'mismatch')

    def test_duplicate_keys(self):
        with self.assertRaises(v.Invalid): v.strict_load(b'{"x":1,"x":2}')

    def test_float_nan(self):
        for data in (b'1.0', b'NaN', b'Infinity', b'-Infinity'):
            with self.subTest(data=data), self.assertRaises(v.Invalid): v.strict_load(data)

    def test_parser_budgets(self):
        for data in (b' '* (v.MAX_JSON+1), b'['*30+b'0'+b']'*30, b'['+b'0,'*1024+b'0]'):
            with self.assertRaises(v.Invalid): v.strict_load(data)

    def test_integer_parser_budget(self):
        for data in (b'9'*100000, b'9007199254740992', b'-9007199254740992'):
            with self.assertRaises(v.Invalid): v.strict_load(data)

    def test_surrogate(self):
        with self.assertRaises(v.Invalid): v.strict_load(b'"\\ud800"')

    def test_wrong_shape(self):
        for data in (None, [], 5, True, {'version':'unknown'}):
            with self.subTest(data=data), self.assertRaises(v.Invalid): v.verify(data)

    def test_unknown_fields_paths(self):
        b = copy.deepcopy(LITERAL); b['final_output']['path'] = '../../private'
        with self.assertRaises(v.Invalid): v.verify(b)

    def test_bool_size(self):
        b = copy.deepcopy(LITERAL); b['instruction']['size'] = False
        with self.assertRaises(v.Invalid): v.verify(b)

    def test_unsafe_integer(self):
        b = copy.deepcopy(LITERAL); b['instruction']['size'] = 2**53
        with self.assertRaises(v.Invalid): v.verify(b)

    def test_duplicate_names(self):
        b = copy.deepcopy(LITERAL); b['final_output']['name'] = 'instruction'
        with self.assertRaises(v.Invalid): v.verify(b)

    def test_digest_tamper(self):
        b = copy.deepcopy(LITERAL); b['receipt_digest'] = '0'*64
        self.assertEqual(v.verify(b)['evidence_chain']['status'], 'mismatch')

    def test_instruction_tamper(self):
        b = copy.deepcopy(LITERAL); b['instruction']['sha256'] = '0'*64
        self.assertEqual(v.verify(b)['evidence_chain']['status'], 'mismatch')

    def test_order_truncation(self):
        b = with_tools(); self.assertEqual(v.verify(b)['evidence_chain']['status'], 'match')
        for variant in ('reorder', 'truncate', 'previous', 'index'):
            c = copy.deepcopy(b)
            if variant == 'reorder': c['tools'].reverse()
            if variant == 'truncate': c['tools'].pop()
            if variant == 'previous': c['tools'][1]['previous'] = '0'*64
            if variant == 'index': c['tools'][0]['index'] = 1
            self.assertEqual(v.verify(c)['evidence_chain']['status'], 'mismatch')

    def test_signature_missing_no_trust(self):
        self.assertEqual(v.verify(LITERAL, trusted_key=PUBLIC)['signature']['status'], 'missing')
        self.assertEqual(v.verify(envelope(signature={'algorithm':'Ed25519','value':SIG}))['signature']['status'], 'unchecked')

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional cryptography unavailable')
    def test_signature_literal_oracle(self):
        b = envelope(signature={'algorithm':'Ed25519','value':SIG})
        self.assertEqual(v.verify(b, trusted_key=PUBLIC)['signature']['status'], 'match')
        self.assertEqual(v.verify(b, trusted_key='00'*32)['signature']['status'], 'mismatch')
        b['bundle']['final_output']['sha256'] = '0'*64
        self.assertEqual(v.verify(b, trusted_key=PUBLIC)['signature']['status'], 'mismatch')

    def test_signature_backend_unavailable(self):
        original = builtins.__import__
        def blocked(name, *a, **kw):
            if name.startswith('cryptography'): raise ImportError('intentional unavailable fixture')
            return original(name, *a, **kw)
        with patch('builtins.__import__', side_effect=blocked):
            r = v.verify(envelope(signature={'algorithm':'Ed25519','value':SIG}), trusted_key=PUBLIC)
        self.assertEqual(r['signature']['status'], 'unchecked'); self.assertFalse(r['signature']['available'])

    def test_key_substitution(self):
        b = envelope(signature={'algorithm':'Ed25519','value':SIG,'public_key':PUBLIC})
        self.assertEqual(v.verify(b, trusted_key=PUBLIC)['signature']['status'], 'mismatch')

    def test_signature_invalid_length(self):
        b = envelope(signature={'algorithm':'Ed25519','value':'00'})
        self.assertEqual(v.verify(b, trusted_key=PUBLIC)['signature']['status'], 'mismatch')

    def test_batch_literal_oracle(self):
        b = envelope(batch={'leaf_index':0,'leaf_count':1,'siblings':[]})
        self.assertEqual(v.verify(b,batch_root=ROOT)['batch']['status'], 'match')
        self.assertEqual(v.verify(b,batch_root='0'*64)['batch']['status'], 'mismatch')
        self.assertEqual(v.verify(b)['batch']['status'], 'unchecked')

    def test_batch_geometry(self):
        for proof in ({'leaf_index':1,'leaf_count':1,'siblings':[]}, {'leaf_index':0,'leaf_count':2,'siblings':[]}, {'leaf_index':0,'leaf_count':1,'siblings':['0'*64]}, {'leaf_index':False,'leaf_count':1,'siblings':[]}, {'leaf_index':2,'leaf_count':3,'siblings':['0'*64,'0'*64]}):
            self.assertEqual(v.verify(envelope(batch=proof),batch_root=ROOT)['batch']['status'], 'mismatch')

    def test_batch_multilevel(self):
        # Independent oracle uses direct hashlib; nontrivial left/right and odd duplication.
        leaves = [hashlib.sha256(b'\0'+bytes.fromhex(RECEIPT)).digest(), hashlib.sha256(b'other').digest(), hashlib.sha256(b'third').digest()]
        parent = lambda l,r: hashlib.sha256(b'\1'+l+r).digest()
        root = parent(parent(leaves[0],leaves[1]),parent(leaves[2],leaves[2])).hex()
        b = envelope(batch={'leaf_index':0,'leaf_count':3,'siblings':[leaves[1].hex(),parent(leaves[2],leaves[2]).hex()]})
        self.assertEqual(v.verify(b,batch_root=root)['batch']['status'], 'match')
        b['batch']['leaf_index']=1
        self.assertEqual(v.verify(b,batch_root=root)['batch']['status'], 'mismatch')

    def test_provider_report_never_inclusion(self):
        r = v.verify(envelope(provider_report={'included':True}))['inclusion']
        self.assertEqual(r['provider_report']['status'], 'unchecked')
        self.assertEqual(r['merkle_inclusion']['status'], 'missing')

    def test_offline_synthetic_inclusion(self):
        r = v.verify(envelope(inclusion=inclusion()), trusted_header=ANCHOR, commitment='6162')['inclusion']
        self.assertEqual(r['transaction_commitment']['status'], 'match')
        self.assertEqual(r['merkle_inclusion']['status'], 'match')
        self.assertEqual(r['header_anchor']['status'], 'match')
        self.assertEqual(r['selected_chain']['status'], 'unchecked')

    def test_inclusion_no_trust(self):
        r = v.verify(envelope(inclusion=inclusion()))['inclusion']
        self.assertEqual(r['transaction_commitment']['status'], 'unchecked')
        self.assertEqual(r['header_anchor']['status'], 'unchecked')
        self.assertEqual(r['merkle_inclusion']['status'], 'match')

    def test_inclusion_wrong_anchor_and_commitment(self):
        r = v.verify(envelope(inclusion=inclusion()), trusted_header='0'*64, commitment='6261')['inclusion']
        self.assertEqual(r['header_anchor']['status'], 'mismatch')
        self.assertEqual(r['transaction_commitment']['status'], 'mismatch')
        self.assertEqual(r['merkle_inclusion']['status'], 'match')

    def test_inclusion_tampering(self):
        for field,value in (('txid','0'*64),('header','00'*80),('rawtx',RAW+'00'),('index',1),('index',True),('siblings',['0'*64]*33)):
            inc = inclusion(); inc[field]=value
            self.assertEqual(v.verify(envelope(inclusion=inc), commitment='6162')['inclusion']['merkle_inclusion']['status'], 'mismatch')

    def test_tx_canonicality(self):
        for raw in (bytes.fromhex(RAW[:8]+'fd0100'+RAW[10:]), bytes.fromhex(RAW[:-2]), bytes.fromhex(RAW+'00')):
            with self.assertRaises(v.Invalid): v.output_scripts(raw)

    def test_merkle_branch_orientation(self):
        # Synthetic two-leaf header; oracle is direct double-SHA256, not verifier helpers.
        dbl = lambda data: hashlib.sha256(hashlib.sha256(data).digest()).digest()
        sibling = hashlib.sha256(b'synthetic sibling').digest()
        node = dbl(RAW and bytes.fromhex(RAW))
        for index in (0, 1):
            inc = inclusion()
            root = dbl(node+sibling if index == 0 else sibling+node)
            head = bytearray.fromhex(HEADER); head[36:68] = root
            inc.update(index=index, siblings=[sibling[::-1].hex()], header=head.hex())
            self.assertEqual(v.verify(envelope(inclusion=inc))['inclusion']['merkle_inclusion']['status'], 'match')
            inc['index'] = 1-index
            self.assertEqual(v.verify(envelope(inclusion=inc))['inclusion']['merkle_inclusion']['status'], 'mismatch')

    def test_no_substring_opreturn(self):
        inc = inclusion()
        # Payload appears in a different pushed string; must not match a substring.
        inc['rawtx'] = RAW.replace('05006a026162', '06006a03616263')
        raw = bytes.fromhex(inc['rawtx'])
        dbl = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
        inc['txid'] = dbl(raw)[::-1].hex()
        self.assertEqual(v.verify(envelope(inclusion=inc), commitment='6162')['inclusion']['transaction_commitment']['status'], 'mismatch')

    def test_invalid_sidecar_shapes(self):
        for field in ('signature', 'batch', 'inclusion'):
            for shape in (False, [], 'invalid'):
                b = envelope(**{field:shape})
                r = v.verify(b, trusted_key=PUBLIC, batch_root=ROOT, commitment='6162')
                check = r['inclusion']['merkle_inclusion'] if field == 'inclusion' else r[field]
                self.assertEqual(check['status'], 'mismatch')

    def test_library_float_and_recursive(self):
        b = copy.deepcopy(LITERAL); b['instruction']['size'] = 0.0
        with self.assertRaises(v.Invalid): v.verify(b)
        cyclic = {}; cyclic['self'] = cyclic
        with self.assertRaises(v.Invalid): v.verify(cyclic)

    def test_legacy_explicit_adapter(self):
        b = {'format':'independent-v1', 'instruction_sha256':'0'*64, 'artifacts':[], 'events':[]}
        genesis = {k:b[k] for k in ('format', 'instruction_sha256', 'artifacts')}
        b['chain_head'] = hashlib.sha256(b'hermes-independent-chain-v1\0'+json.dumps(genesis,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(v.verify(b)['evidence_chain']['status'], 'match')
        b['chain_head']='0'*64
        self.assertEqual(v.verify(b)['evidence_chain']['status'], 'mismatch')

    def test_cli(self):
        cmd = [sys.executable, '-I', str(Path(v.__file__)), str(HERE/'receipt_vectors/verifier/literal.json'), '--artifact', 'output='+str(HERE/'receipt_vectors/verifier/output.txt')]
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout); self.assertEqual(r['artifact_bytes'][1]['status'], 'match')
        p = subprocess.run(cmd+['--artifact','output=again'], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(p.returncode, 2)

if __name__ == '__main__':
    unittest.main(verbosity=2)
