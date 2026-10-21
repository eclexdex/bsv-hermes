import base64
import json
import unittest
from unittest.mock import patch
from pathlib import Path
from bsv_hermes.receipts import signature as m

# RFC 8032 section 7.1 public test seed; never a user/funded key.
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
BUNDLE = b'{"fixture":"synthetic-neverfunded","version":1}'

def fixture():
    return m.sign_synthetic(BUNDLE, key_ref='synthetic:rfc8032-1', resolve_key=lambda ref: SEED,
                            issued_at=100, expires_at=200, nonce='00'*16)

class Tests(unittest.TestCase):
    def setUp(self):
        try:
            m._crypto()
        except ImportError:
            self.skipTest('optional pinned cryptography 48.0.0 unavailable')
        self.s = fixture()
    def verify(self, **kw):
        args = dict(trusted_public_key=PUBLIC, expected_fingerprint=m.fingerprint(PUBLIC),
                    expected_domain=m.DOMAIN, now=150)
        args.update(kw)
        return m.verify(BUNDLE, self.s, **args)
    def test_valid(self):
        self.assertEqual(self.verify()['status'], 'match')
        self.assertEqual(self.verify()['replay'], 'unchecked')
    def test_wrong_key(self):
        self.assertEqual(self.verify(trusted_public_key=bytes(32))['reason'], 'trusted_key_mismatch')
    def test_fingerprint(self):
        self.assertEqual(self.verify(expected_fingerprint='0'*64)['status'], 'mismatch')
    def test_domain(self):
        self.assertEqual(self.verify(expected_domain='other')['status'], 'mismatch')
    def test_bundle_tamper(self):
        self.assertEqual(m.verify(BUNDLE+b' ', self.s, trusted_public_key=PUBLIC,
                         expected_fingerprint=m.fingerprint(PUBLIC), expected_domain=m.DOMAIN,
                         now=150)['reason'], 'bundle_digest_mismatch')
    def test_signed_fields(self):
        for field, value in [('nonce','11'*16), ('expires_at',201), ('issued_at',99), ('signature',base64.b64encode(bytes(64)).decode())]:
            with self.subTest(field=field):
                self.s=fixture(); self.s[field]=value
                self.assertEqual(self.verify()['status'], 'mismatch')
    def test_expiry_boundaries(self):
        self.assertEqual(self.verify(now=100)['status'], 'match')
        self.assertEqual(self.verify(now=199)['status'], 'match')
        self.assertEqual(self.verify(now=200)['reason'], 'expired')
        self.assertEqual(self.verify(now=99)['reason'], 'not_yet_valid')
    def test_replay(self):
        token=self.verify()['replay_token']
        self.assertEqual(self.verify(seen_tokens={token})['reason'], 'replay_seen')
        self.assertEqual(self.verify(seen_tokens=set())['replay'], 'not_seen')
    def test_no_trust(self):
        self.assertEqual(self.verify(trusted_public_key=None)['status'], 'unchecked')
    def test_absent(self):
        self.s=None
        self.assertEqual(self.verify()['status'], 'missing')
    def test_unavailable(self):
        with patch.object(m, '_crypto', side_effect=ImportError):
            self.assertEqual(self.verify()['status'], 'unchecked')
    def test_strict_types(self):
        for field, value in [('version',True), ('issued_at',True), ('expires_at',200.0), ('nonce','z'*32)]:
            self.s=fixture(); self.s[field]=value
            self.assertEqual(self.verify()['status'], 'mismatch')
    def test_parser(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b' '*4097]:
            with self.assertRaises(ValueError): m.loads_sidecar(raw)
        self.assertEqual(m.loads_sidecar(json.dumps(self.s).encode()), self.s)
    def test_reference_restriction(self):
        with self.assertRaises(ValueError):
            m.sign_synthetic(BUNDLE, key_ref='/real/key', resolve_key=lambda r: SEED,
                             issued_at=100, expires_at=200, nonce='00'*16)
    def test_rfc8032_independent_oracle(self):
        Private, Public, _, _ = m._crypto()
        expected=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertEqual(Private.from_private_bytes(SEED).sign(b''), expected)
        Public.from_public_bytes(PUBLIC).verify(expected,b'')
    def test_literal_vector(self):
        with (Path(__file__).parent / 'receipt_vectors/signature.json').open() as f: v=json.load(f)
        self.assertEqual(self.s,v['sidecar'])
        self.assertEqual(m.preimage(self.s).hex(),v['preimage_hex'])

if __name__ == '__main__': unittest.main()
