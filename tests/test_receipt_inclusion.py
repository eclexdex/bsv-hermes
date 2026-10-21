import copy
import json
import struct
import unittest
from pathlib import Path
from bsv_hermes.receipts.inclusion import verify, outputs, strict_json, h256

# Public, unspendable genesis transaction; not a receipt or publication of this work.
GENESIS_TX = ('0100000001' + '00'*32 + 'ffffffff4d04ffff001d010445' +
 '5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73' +
 'ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000')
GENESIS_ID = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
GENESIS_HEADER = ('01000000'+'00'*32+'3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'+'29ab5f49ffff001d1dac2b7c')
GENESIS_HASH = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

def synthetic(script=bytes.fromhex('006a04deadbeef')):
    # Deliberately nonexistent never-funded prevout. No key/signature.
    return ('0100000001'+'11'*32+'0000000000ffffffff01'+'0000000000000000'+bytes([len(script)]).hex()+script.hex()+'00000000')

def fixture():
    return {'raw_tx_hex':GENESIS_TX,'header_hex':GENESIS_HEADER,'merkle_path':{'index':0,'siblings':[]},'fixture_label':'public historical genesis; not our publication'}

class Tests(unittest.TestCase):
    def test_public_literal_oracle(self):
        r = verify(fixture(),expected_txid=GENESIS_ID)
        self.assertEqual(r['txid']['status'],'match')
        self.assertEqual(r['header_hash'],GENESIS_HASH)
        self.assertEqual(r['merkle_header']['status'],'match')
        self.assertEqual(r['header_pow']['status'],'match')
        self.assertEqual(r['selected_chain']['status'],'unchecked')
        self.assertFalse(r['spv_verified'])
    def test_genesis_is_not_commitment(self):
        self.assertEqual(verify(fixture(),'deadbeef')['commitment']['status'],'mismatch')
    def test_commitment_full_push(self):
        e={'raw_tx_hex':synthetic()}
        self.assertEqual(verify(e,'deadbeef')['commitment']['status'],'match')
        self.assertEqual(verify(e,'adbe')['commitment']['status'],'mismatch')
        self.assertEqual(verify({'raw_tx_hex':synthetic(b'\x04\xde\xad\xbe\xef')},'deadbeef')['commitment']['status'],'mismatch')
    def test_pushdata1(self):
        self.assertEqual(verify({'raw_tx_hex':synthetic(bytes.fromhex('6a4c04deadbeef'))},'deadbeef')['commitment']['status'],'match')
    def test_txid_tamper(self):
        e=fixture(); e['raw_tx_hex']=e['raw_tx_hex'][:-8]+'01000000'
        r=verify(e,expected_txid=GENESIS_ID)
        self.assertEqual(r['txid']['status'],'mismatch'); self.assertEqual(r['merkle_header']['status'],'mismatch')
    def test_header_tamper(self):
        e=fixture(); e['header_hex']=GENESIS_HEADER[:72]+'00'*32+GENESIS_HEADER[136:]
        self.assertEqual(verify(e)['merkle_header']['status'],'mismatch')
    def test_wrong_path(self):
        e=fixture(); e['merkle_path']={'index':0,'siblings':['11'*32]}
        self.assertEqual(verify(e)['merkle_header']['status'],'mismatch')
    def test_bool_index(self):
        e=fixture(); e['merkle_path']['index']=False
        self.assertEqual(verify(e)['merkle_header']['status'],'mismatch')
    def test_nontrivial_path_endian_order(self):
        raw=synthetic(); leaf=h256(bytes.fromhex(raw)); other=bytes.fromhex('22'*32)
        root=h256(other+leaf)
        header=bytes.fromhex(GENESIS_HEADER); header=header[:36]+root+header[68:]
        e={'raw_tx_hex':raw,'header_hex':header.hex(),'merkle_path':{'index':1,'siblings':[other[::-1].hex()]}}
        self.assertEqual(verify(e,'deadbeef')['merkle_header']['status'],'match')
        e['merkle_path']['index']=0
        self.assertEqual(verify(e)['merkle_header']['status'],'mismatch')
    def test_provider_lies(self):
        r=verify({'provider_report':{'mined':True,'spv_verified':True},'submitted':True,'selected_chain':{'validated':True}})
        self.assertEqual(r['provider_report']['status'],'unchecked')
        self.assertEqual(r['submission']['status'],'unchecked')
        self.assertEqual(r['merkle_header']['status'],'missing')
        self.assertEqual(r['selected_chain']['status'],'unchecked'); self.assertFalse(r['spv_verified'])
    def test_no_independent_txid(self):
        e=fixture(); e['txid']=GENESIS_ID
        self.assertEqual(verify(e)['txid']['status'],'unchecked')
    def test_bad_transactions(self):
        for raw in ['', '00', synthetic()+'00', synthetic().replace('0100000001','01000000fd0100',1)]:
            self.assertEqual(verify({'raw_tx_hex':raw})['raw_transaction']['status'],'mismatch')
    def test_duplicate_json(self):
        with self.assertRaises(ValueError): strict_json('{"a":1,"a":2}')
    def test_negative_pow(self):
        e=fixture(); e['header_hex']=GENESIS_HEADER[:144]+'ffff801d'+GENESIS_HEADER[152:]
        self.assertEqual(verify(e)['header_pow']['status'],'mismatch')
    def test_budget(self):
        e=fixture(); e['merkle_path']['siblings']=['00'*32]*33
        self.assertEqual(verify(e)['merkle_header']['status'],'mismatch')
    def test_empty(self):
        r=verify({})
        self.assertEqual(r['raw_transaction']['status'],'missing'); self.assertFalse(r['spv_verified'])

if __name__=='__main__': unittest.main()
