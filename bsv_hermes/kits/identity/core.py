"""Original custody-free identity commitments. No host discovery or I/O at import."""
import hashlib
import json
import re
import secrets
import os
import stat
from pathlib import Path, PurePosixPath

MAX_FILES = 128
MAX_TOTAL = 1048576
EXTENSIONS = {'.md', '.py', '.json', '.yaml', '.yml', '.toml', '.txt', '.lock', '.js', '.ts'}


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 240 or '\\' in name:
        raise ValueError('invalid relative name')
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')) or len(p.parts) > 8:
        raise ValueError('invalid relative name')
    if any(x.startswith('.') or re.search(r'(secret|credential|wallet|session|private|token|password)', x, re.I) for x in p.parts):
        raise ValueError('sensitive path rejected')
    if p.name.lower() in ('config.yaml', 'config.yml', 'id_rsa', 'id_ed25519') or p.suffix.lower() not in EXTENSIONS:
        raise ValueError('file class rejected')
    return p.parts


def files(root, names):
    """Read only an explicit file allowlist. POSIX descriptor traversal prevents symlink races."""
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_FILES or any(not isinstance(n, str) for n in names):
        raise ValueError('file count invalid')
    if len(set(names)) != len(names):
        raise ValueError('duplicate file')
    parts = [safe_name(n) for n in names]
    root = Path(root).absolute()
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('symlink root rejected')
    if any(p.name.startswith('.') or re.search(r'(secret|credential|wallet|session)', p.name, re.I) for p in (root, *root.parents) if p.name):
        raise ValueError('sensitive root rejected')
    result, total = [], 0
    try:
        rootfd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in root.parts[1:]:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
                os.close(rootfd)
                rootfd = nxt
        except BaseException:
            os.close(rootfd)
            raise
        try:
            for name, segments in zip(names, parts):
                fd = os.dup(rootfd)
                try:
                    for segment in segments[:-1]:
                        nxt = os.open(segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd)
                        fd = nxt
                    leaf = os.open(segments[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    try:
                        if not stat.S_ISREG(os.fstat(leaf).st_mode):
                            raise ValueError('regular files only')
                        data = os.read(leaf, MAX_BYTES + 1)
                        bounded(data)
                    finally:
                        os.close(leaf)
                finally:
                    os.close(fd)
                total += len(data)
                if total > MAX_TOTAL:
                    raise ValueError('aggregate size limit')
                result.append({'path': name, 'data': data})
        finally:
            os.close(rootfd)
    except OSError:
        raise ValueError('allowlisted file unavailable or unsafe') from None
    return result


def manifest_preimage(entries):
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise ValueError('manifest count invalid')
    rows, seen, total = [], set(), 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'path', 'data'}:
            raise ValueError('invalid manifest entry')
        name = entry['path']
        safe_name(name)
        if name in seen:
            raise ValueError('duplicate file')
        seen.add(name)
        data = bounded(entry['data'])
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError('aggregate size limit')
        rows.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    return canonical({'format': 'sorted-file-sha256-v1', 'files': sorted(rows, key=lambda row: row['path'])})


def manifest(entries, kind='instructions', network='testnet', private=False):
    if kind not in ('instructions', 'release'):
        raise ValueError('invalid manifest purpose')
    return seal(manifest_preimage(entries), kind, network, private)


def verify_manifest(receipt, entries, nonce=''):
    if not isinstance(receipt, dict) or receipt.get('kind') not in ('instructions', 'release'):
        return False
    return verify(receipt, manifest_preimage(entries), nonce)

def release(entries, network='testnet', private=False):
    """Opaque file integrity, NOT dependency resolution, malware or signature checks."""
    return manifest(entries, 'release', network, private)


def changes(before, after):
    a = {row['path']: row for row in json.loads(manifest_preimage(before))['files']}
    b = {row['path']: row for row in json.loads(manifest_preimage(after))['files']}
    return {'added': sorted(b.keys() - a.keys()), 'removed': sorted(a.keys() - b.keys()),
            'changed': sorted(k for k in a.keys() & b.keys() if a[k] != b[k])}

POSTURE_FIELDS = {'hermes_version', 'approval_mode', 'network_access', 'max_iterations', 'telemetry_enabled'}


def posture_preimage(fields):
    """Accept ONLY a caller-authored non-secret projection, never a host config dump."""
    if not isinstance(fields, dict) or set(fields) != POSTURE_FIELDS:
        raise ValueError('exact non-secret posture fields required')
    if not isinstance(fields['hermes_version'], str) or not re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', fields['hermes_version']):
        raise ValueError('invalid public version')
    if fields['approval_mode'] not in ('required', 'disabled', 'unknown') or fields['network_access'] not in ('disabled', 'allowlisted', 'unknown'):
        raise ValueError('invalid public posture enum')
    if type(fields['max_iterations']) is not int or not 1 <= fields['max_iterations'] <= 10000 or type(fields['telemetry_enabled']) is not bool:
        raise ValueError('invalid public posture scalar')
    return canonical({'format': 'non-secret-posture-v1', 'fields': fields})


def posture(fields, network='testnet', private=False):
    return seal(posture_preimage(fields), 'posture', network, private)

MAX_BYTES = 65536
KINDS = ('soul', 'instructions', 'posture', 'release')
DOMAIN = 'bsv-hermes-identity/v1'


def canonical(value):
    """Legacy JSON bytes, including finite floats; no Unicode normalization.

    Preserve historical direct-library commitments. Native input schemas reject
    floats; new receipt-v1 has a separate strict integer-only profile. Nonfinite
    values remain forbidden. This helper is not RFC 8785 / cross-language JCS.
    """
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def bounded(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('invalid or oversized byte input')
    return data


def commitment(data, kind, network, nonce=''):
    bounded(data)
    if kind not in KINDS or network not in ('mainnet', 'testnet'):
        raise ValueError('unsupported purpose or network')
    if not isinstance(nonce, str) or (nonce and not re.fullmatch('[0-9a-f]{64}', nonce)):
        raise ValueError('nonce must be 32-byte lowercase hex')
    header = canonical({'domain': DOMAIN, 'kind': kind, 'network': network,
                        'representation': 'exact-bytes-v1', 'nonce': nonce})
    return hashlib.sha256(len(header).to_bytes(4, 'big') + header + data).hexdigest()


def seal(data, kind, network, private=False):
    if type(private) is not bool:
        raise ValueError('private must be boolean')
    nonce = secrets.token_hex(32) if private else ''
    digest = commitment(data, kind, network, nonce)
    public = {'domain': DOMAIN, 'kind': kind, 'network': network,
              'representation': 'exact-bytes-v1', 'commitment': digest,
              'private_nonce': private,
              'anchor_plan': {'status': 'unsigned-not-submitted', 'payload_hex': digest,
                              'publication_consent_required': True,
                              'chain_evidence': 'none', 'authorship': 'not-established'}}
    return public, {'nonce': nonce}


def soul(data, network='testnet', private=False):
    return seal(bounded(data), 'soul', network, private)


def exact_receipt(actual, expected):
    """Walk only the fixed expected schema; never serialize untrusted nested values."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_receipt(actual[k], v) for k, v in expected.items())
    return actual == expected


def verify(receipt, data, nonce=''):
    """Exact receipt reconstruction: no proof of signer, time or chain inclusion."""
    try:
        expected, _ = seal(data, receipt['kind'], receipt['network'], False)
        expected['private_nonce'] = bool(nonce)
        expected['commitment'] = commitment(data, receipt['kind'], receipt['network'], nonce)
        expected['anchor_plan']['payload_hex'] = expected['commitment']
        return exact_receipt(receipt, expected)
    except (KeyError, TypeError, ValueError):
        return False
