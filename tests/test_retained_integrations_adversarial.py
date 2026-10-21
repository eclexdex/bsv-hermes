import unittest, hashlib, copy, json, random, socket
from unittest.mock import patch
from bsv_hermes.kits.integrations import core
from bsv_hermes.kits.integrations.operations import dispatch, PARAMETERS

class Adversarial(unittest.TestCase):

    def test_odd_nonce_rejected(self):
        with self.assertRaises(ValueError):
            core.batch({'digests': ['11' * 32], 'network': 'testnet', 'nonce': 'a' * 33})

    def test_batch_sizes_and_tamper(self):
        for count in (1, 2, 3, 5, 17, 256):
            ds = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(count)]
            a = {'digests': ds, 'network': 'mainnet', 'nonce': '00' * 16}
            b = core.batch(a)
            for idx in (0, count - 1):
                p = b['proofs'][idx]
                v = {'digest': ds[idx], 'proof': p, 'commitment': b['commitment'], 'network': 'mainnet', 'nonce': '00' * 16}
                self.assertTrue(core.verify_batch(v))
                for field, value in [('digest', 'ff' * 32), ('nonce', '01' * 16), ('commitment', 'ff' * 32), ('network', 'testnet')]:
                    self.assertFalse(core.verify_batch(dict(v, **{field: value})))
                q = copy.deepcopy(v)
                q['proof']['siblings'].append('00' * 32)
                self.assertFalse(core.verify_batch(q))
                if p['siblings']:
                    q = copy.deepcopy(v)
                    q['proof']['siblings'][0] = 'ff' * 32
                    self.assertFalse(core.verify_batch(q))
        leaf = hashlib.sha256(b'\x00' + bytes(4) + bytes.fromhex('11' * 32)).digest()
        raw = json.dumps({'domain': core.DOMAIN, 'count': 1, 'root': leaf.hex(), 'network': 'testnet', 'nonce': '00' * 16}, sort_keys=True, separators=(',', ':')).encode()
        expected = hashlib.sha256(b'\x02' + raw).hexdigest()
        self.assertEqual(core.batch({'digests': ['11' * 32], 'network': 'testnet', 'nonce': '00' * 16})['commitment'], expected)

    def test_invalid_inputs_do_not_echo(self):
        for action in PARAMETERS:
            for value in ({}, None, [], {'password': 'DO-NOT-ECHO-CANARY'}, {'x': 'x' * 70000}):
                r = dispatch(action, value)
                self.assertFalse(r['ok'])
                self.assertNotIn('DO-NOT-ECHO-CANARY', json.dumps(r))
        for value in (float('nan'), float('inf'), 1.5, 2 ** 60):
            with self.assertRaises(ValueError):
                core.canonical(value)
        deep = {}
        cur = deep
        for i in range(20):
            cur['x'] = {}
            cur = cur['x']
        with self.assertRaises(ValueError):
            core.canonical(deep)

    def test_no_network(self):
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('network')):
            r = dispatch('content', {'network': 'mainnet', 'content_hex': '616263', 'expected_sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'})
            self.assertTrue(r['ok'])
            self.assertTrue(r['data']['digest_match'])
if __name__ == '__main__':
    unittest.main()
