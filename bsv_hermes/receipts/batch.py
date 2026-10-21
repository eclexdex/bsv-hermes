"""Offline ordered receipt batches. Stdlib only; no authority or execution claims."""
import hashlib
import json
import re

VERSION = 'bsv-hermes-receipt-batch/1'
MAX_LEAVES = 1024
MAX_RECEIPT_BYTES = 1048576
MAX_BATCH_BYTES = 8388608
HEX = re.compile(r'^[0-9a-f]{64}$')
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tagged(tag, value):
    return digest((VERSION + '/' + tag + '\0').encode('ascii') + canonical(value))


def hex32(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise ValueError('expected lowercase 32-byte hex')
    return value


def count_ok(value):
    if type(value) is not int or not 1 <= value <= MAX_LEAVES:
        raise ValueError('invalid leaf count')


def leaf_hash(receipt_id, receipt_sha256, nonce_hex):
    if type(receipt_id) is not str or not ID.fullmatch(receipt_id):
        raise ValueError('invalid receipt ID')
    return tagged('leaf', {'receipt_id': receipt_id, 'receipt_sha256': hex32(receipt_sha256), 'nonce_hex': hex32(nonce_hex)})


def parent(left, right):
    return tagged('node', [hex32(left), hex32(right)])


def commitment(root, count, network):
    count_ok(count)
    if network not in ('mainnet', 'testnet'):
        raise ValueError('unsupported network')
    return tagged('commitment', {'root': hex32(root), 'count': count, 'network': network})


def build_batch(receipts, *, nonces, network='mainnet', export_private_proofs=False):
    """receipts is an explicit ordered list of (ID, exact completed bundle bytes).

    Caller is responsible for completion/schema validation. No execution truth is
    inferred. Fresh cryptographically random 32-byte nonce per receipt recommended;
    explicit nonces allow reproducible fixtures. Never reuse production nonces.
    """
    if type(receipts) is not list or type(nonces) is not list:
        raise ValueError('ordered lists required')
    count_ok(len(receipts))
    if len(receipts) != len(nonces):
        raise ValueError('missing nonce/leaf')
    if type(export_private_proofs) is not bool:
        raise ValueError('explicit boolean export required')
    entries, leaves, ids, seen_nonces, size = [], [], set(), set(), 0
    for item, nonce in zip(receipts, nonces):
        if type(item) not in (tuple, list) or len(item) != 2:
            raise ValueError('expected ID and exact bytes')
        rid, data = item
        if type(data) is not bytes or not 1 <= len(data) <= MAX_RECEIPT_BYTES:
            raise ValueError('receipt byte bounds')
        size += len(data)
        if size > MAX_BATCH_BYTES:
            raise ValueError('batch byte bounds')
        h = leaf_hash(rid, digest(data), nonce)
        if rid in ids or nonce in seen_nonces:
            raise ValueError('duplicate ID or nonce')
        ids.add(rid)
        seen_nonces.add(nonce)
        entries.append({'receipt_id': rid, 'receipt_sha256': digest(data), 'nonce_hex': nonce})
        leaves.append(h)
    levels = [leaves]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append([parent(row[i], row[i+1] if i+1 < len(row) else row[i]) for i in range(0, len(row), 2)])
    root = levels[-1][0]
    manifest = {'version': VERSION, 'network': network, 'count': len(leaves), 'root': root,
                'commitment': commitment(root, len(leaves), network), 'ordering': 'explicit-input-order',
                'odd_node': 'duplicate-last', 'source_status': 'unverified-source'}
    result = {'manifest': manifest}
    if export_private_proofs:
        proofs = []
        for index, entry in enumerate(entries):
            path, pos = [], index
            for row in levels[:-1]:
                sibling = pos ^ 1
                path.append(row[sibling] if sibling < len(row) else row[pos])
                pos //= 2
            proofs.append(dict(entry, version=VERSION, index=index, count=len(leaves), network=network, siblings=path))
        result['private_proofs'] = proofs
    return result


def verify_proof(proof, *, expected_commitment, receipt_bytes=None):
    """Only batch membership, relative to caller-specified trusted commitment.

    Missing receipt bytes checks the committed digest only, not artifact bytes.
    Invalid and incomplete openings return False; no publication/signature claim.
    """
    try:
        if type(proof) is not dict or set(proof) != {'version','index','count','network','siblings','receipt_id','receipt_sha256','nonce_hex'}:
            return False
        if proof['version'] != VERSION:
            return False
        count = proof['count']
        count_ok(count)
        pos = proof['index']
        if type(pos) is not int or not 0 <= pos < count:
            return False
        siblings = proof['siblings']
        if type(siblings) is not list or len(siblings) > 10:
            return False
        if receipt_bytes is not None:
            if type(receipt_bytes) is not bytes or not 1 <= len(receipt_bytes) <= MAX_RECEIPT_BYTES or digest(receipt_bytes) != proof['receipt_sha256']:
                return False
        node = leaf_hash(proof['receipt_id'], proof['receipt_sha256'], proof['nonce_hex'])
        width, step = count, 0
        while width > 1:
            if step >= len(siblings):
                return False
            sibling = hex32(siblings[step])
            if pos == width - 1 and width % 2 and sibling != node:
                return False
            node = parent(sibling, node) if pos % 2 else parent(node, sibling)
            pos //= 2
            width = (width + 1) // 2
            step += 1
        return step == len(siblings) and commitment(node, count, proof['network']) == hex32(expected_commitment)
    except (ValueError, TypeError, KeyError):
        return False


def verify_complete_batch(manifest, receipts, *, nonces):
    """Full rebuild detects missing, reordered, added or substituted leaves."""
    try:
        rebuilt = build_batch(receipts, nonces=nonces, network=manifest['network'])
        return rebuilt['manifest'] == manifest
    except (ValueError, TypeError, KeyError):
        return False


def commitment_request(manifest, *, workflow_id):
    """Generate inert native prepare arguments, never call a publisher.

    Existing publisher hashes supplied UTF-8 text: on-chain digest is SHA256(text),
    NOT the Merkle root or inner commitment. Preserve both binding layers.
    """
    if type(manifest) is not dict or set(manifest) != {'version','network','count','root','commitment','ordering','odd_node','source_status'}:
        raise ValueError('invalid manifest')
    if manifest['version'] != VERSION or manifest['network'] != 'mainnet' or manifest['ordering'] != 'explicit-input-order' or manifest['odd_node'] != 'duplicate-last' or manifest['source_status'] != 'unverified-source':
        raise ValueError('invalid manifest/domain')
    if commitment(manifest['root'], manifest['count'], manifest['network']) != manifest['commitment']:
        raise ValueError('manifest commitment mismatch')
    if type(workflow_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', workflow_id):
        raise ValueError('invalid workflow ID')
    text = canonical({'version': VERSION, 'network': 'mainnet', 'count': manifest['count'], 'commitment': manifest['commitment']}).decode('ascii')
    outer = digest(text.encode('utf-8'))
    return {'status': 'not-prepared-not-signed-not-submitted', 'tool': 'bsv_publish_prepare',
            'arguments': {'workflow_id': workflow_id, 'text': text},
            'expected_text_sha256': outer, 'expected_commitment_script_hex': '006a20' + outer,
            'required_operator_steps': ['review frozen quote and limits', 'independent approve-sign', 'review exact signed txid', 'independent approve-submit'],
            'approval': 'absent', 'publication': 'unchecked', 'signature': 'missing', 'inclusion': 'unchecked'}
