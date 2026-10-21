"""Optional Ed25519 receipt sidecar. No Hermes, wallet, network, or automatic key IO."""
import base64
import hashlib
import json
import re

DOMAIN = 'bsv-hermes/receipt-signature/v1'
PREFIX = b'bsv-hermes/receipt-signature/v1\x00'
PIN = '48.0.0'
MAX_BUNDLE = 8 * 1024 * 1024
FIELDS = {'version', 'domain', 'algorithm', 'public_key_sha256', 'bundle_sha256',
          'issued_at', 'expires_at', 'nonce', 'signature'}


def _crypto():
    import cryptography
    if cryptography.__version__ != PIN:
        raise ImportError('optional cryptography version must be ' + PIN)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey, Ed25519PublicKey, Encoding, PublicFormat


def fingerprint(public_key):
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError('raw Ed25519 public key must be 32 bytes')
    return hashlib.sha256(public_key).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _validate(s, bundle, domain):
    if type(bundle) is not bytes or len(bundle) > MAX_BUNDLE:
        raise ValueError('bundle must be bounded canonical bytes')
    if type(s) is not dict or set(s) != FIELDS:
        raise ValueError('sidecar fields')
    if type(s['version']) is not int or s['version'] != 1 or s['algorithm'] != 'Ed25519':
        raise ValueError('unsupported version/algorithm')
    if type(domain) is not str or domain != DOMAIN or s['domain'] != domain:
        raise ValueError('domain mismatch')
    for name in ('public_key_sha256', 'bundle_sha256'):
        if type(s[name]) is not str or not re.fullmatch('[0-9a-f]{64}', s[name]):
            raise ValueError('invalid digest')
    for name in ('issued_at', 'expires_at'):
        if type(s[name]) is not int or not 0 <= s[name] <= 9007199254740991:
            raise ValueError('invalid timestamp')
    if s['expires_at'] <= s['issued_at']:
        raise ValueError('empty validity interval')
    if type(s['nonce']) is not str or not re.fullmatch('[0-9a-f]{32}', s['nonce']):
        raise ValueError('nonce must be 16 bytes lowercase hex')
    if type(s['signature']) is not str or len(s['signature']) != 88:
        raise ValueError('signature encoding')
    sig = base64.b64decode(s['signature'], validate=True)
    if len(sig) != 64 or base64.b64encode(sig).decode() != s['signature']:
        raise ValueError('signature encoding')
    return sig


def preimage(sidecar):
    return PREFIX + _canonical({k: v for k, v in sidecar.items() if k != 'signature'})


def sign_synthetic(bundle, *, key_ref, resolve_key, issued_at, expires_at, nonce):
    """OFFLINE TEST ONLY. Resolver returns a synthetic raw 32-byte seed.

    key_ref is explicit host configuration, not an agent tool argument. Production
    signing is intentionally absent: parent must implement an approval-bearing
    external signer rather than exposing this fixture helper to model dispatch.
    """
    if type(key_ref) is not str or not key_ref.startswith('synthetic:'):
        raise ValueError('only synthetic key references accepted')
    Private, _, Encoding, PublicFormat = _crypto()
    key = Private.from_private_bytes(resolve_key(key_ref))
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    s = dict(version=1, domain=DOMAIN, algorithm='Ed25519',
             public_key_sha256=fingerprint(public), bundle_sha256=hashlib.sha256(bundle).hexdigest(),
             issued_at=issued_at, expires_at=expires_at, nonce=nonce,
             signature=base64.b64encode(bytes(64)).decode())
    _validate(s, bundle, DOMAIN)
    s['signature'] = base64.b64encode(key.sign(preimage(s))).decode()
    return s


def verify(bundle, sidecar, *, trusted_public_key, expected_fingerprint, expected_domain,
           now, seen_tokens=None):
    """Pure verification; caller owns atomic replay-token consumption.

    Status is signature-only; never consent, execution, artifact or inclusion truth.
    now is explicit UTC Unix seconds. Freshness interval is [issued_at, expires_at).
    """
    def result(status, reason, **extra):
        return dict(status=status, reason=reason, source='unverified_source', **extra)
    if sidecar is None:
        return result('missing', 'signature_absent')
    if trusted_public_key is None or expected_fingerprint is None or expected_domain is None:
        return result('unchecked', 'caller_trust_required')
    try:
        if type(now) is not int or now < 0:
            raise ValueError('explicit integer verification time required')
        sig = _validate(sidecar, bundle, expected_domain)
        fp = fingerprint(trusted_public_key)
        if expected_fingerprint != fp or sidecar['public_key_sha256'] != fp:
            return result('mismatch', 'trusted_key_mismatch')
        if sidecar['bundle_sha256'] != hashlib.sha256(bundle).hexdigest():
            return result('mismatch', 'bundle_digest_mismatch')
        _, Public, _, _ = _crypto()
        Public.from_public_bytes(trusted_public_key).verify(sig, preimage(sidecar))
    except ImportError:
        return result('unchecked', 'crypto_unavailable_or_unpinned')
    except Exception as exc:
        return result('mismatch', 'invalid_signature_or_sidecar', error_type=type(exc).__name__)
    if now < sidecar['issued_at']:
        return result('mismatch', 'not_yet_valid')
    if now >= sidecar['expires_at']:
        return result('mismatch', 'expired')
    token = hashlib.sha256(PREFIX + fp.encode('ascii') + bytes.fromhex(sidecar['nonce'])).hexdigest()
    if seen_tokens is not None and token in seen_tokens:
        return result('mismatch', 'replay_seen', replay_token=token, replay='seen')
    return result('match', 'signature_valid', replay_token=token,
                  replay='unchecked' if seen_tokens is None else 'not_seen',
                  identity='caller_trusted_key_only', execution='unverified')


def loads_sidecar(raw):
    """Bounded strict JSON parser; reject duplicates and nonstandard constants."""
    if type(raw) is not bytes or len(raw) > 4096:
        raise ValueError('sidecar exceeds budget')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate key')
            out[key] = value
        return out
    def bad(value):
        raise ValueError('nonstandard number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)
