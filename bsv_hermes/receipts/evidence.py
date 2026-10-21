"""Versioned composition of independent receipt checks. No Hermes/wallet imports.

No hash-domain translation: v2 sidecars commit canonical complete contract bundles;
the original independent-v1/external-v1 verifier remains an explicit legacy API.
"""
from . import verifier as core
from . import batch
from . import signature, inclusion

ADAPTER = 'bsv-hermes/receipt-evidence/v2'
REPORT = 'bsv-hermes/receipt-report/v2'


def check(status, detail, **extra):
    return dict(status=status, detail=detail, **extra)


def verify(value, approved_artifacts=None, *, batch_commitment=None,
           trusted_key=None, now=None, expected_txid=None, trusted_header=None,
           commitment=None):
    core.bounded_object(value)
    value = core.strict_load(core.canonical(value))
    if type(value) is not dict:
        raise core.Invalid('receipt object required')
    if 'adapter' in value:
        core.fields(value, ('adapter', 'bundle'), ('batch', 'signature', 'inclusion'))
        if value['adapter'] != ADAPTER:
            raise core.Invalid('unsupported envelope; use explicit legacy verifier for external-v1')
        bundle = value['bundle']
    else:
        bundle, value = value, {'bundle': value}
    if type(bundle) is not dict or bundle.get('version') != 'hermes-receipt/v1':
        raise core.Invalid('hermes-receipt/v1 required')
    report = core.verify(bundle, approved_artifacts)
    items = report['artifact_bytes']
    statuses = {x['status'] for x in items}
    artifact = 'mismatch' if 'mismatch' in statuses else 'missing' if 'missing' in statuses else 'unchecked' if 'unchecked' in statuses else 'match'
    checks = {
        'artifact': check(artifact, 'explicitly granted file bytes only; inspect each item', items=items),
        'chain': report['evidence_chain'],
        'signature': check('missing', 'no signature sidecar'),
        'batch': check('missing', 'no private batch proof'),
        'publication': check('missing', 'no publication evidence'),
        'inclusion': check('missing', 'no offline inclusion evidence', selected_chain=check('unchecked', 'selected-chain validation not implemented')),
    }
    proof = value.get('batch')
    if proof is not None:
        if batch_commitment is None:
            checks['batch'] = check('unchecked', 'caller-selected commitment required')
        else:
            matched = batch.verify_proof(proof, expected_commitment=batch_commitment,
                                         receipt_bytes=core.contract_canonical(bundle))
            checks['batch'] = check('match' if matched else 'mismatch', 'canonical complete bundle bytes in nonce-bearing bsv-hermes-receipt-batch/1 only')
    if 'signature' in value:
        if trusted_key is None or now is None:
            checks['signature'] = check('unchecked', 'explicit caller-trusted public key and verification time required')
        else:
            key = core.hexbytes(trusted_key, 32)
            checks['signature'] = signature.verify(core.contract_canonical(bundle), value['signature'],
                trusted_public_key=key, expected_fingerprint=signature.fingerprint(key),
                expected_domain=signature.DOMAIN, now=now)
    if 'inclusion' in value:
        sidecar = value['inclusion']
        core.fields(sidecar, ('version',), ('raw_tx_hex', 'header_hex', 'merkle_path', 'plan', 'submitted', 'provider_report'))
        if sidecar['version'] != 'bsv-hermes/publication-evidence/v1':
            raise core.Invalid('unsupported publication evidence version')
        if 'merkle_path' in sidecar:
            core.fields(sidecar['merkle_path'], ('index', 'siblings'))
        expected = commitment
        binding = check('unchecked', 'no verified batch-to-publisher binding; supplied expected payload alone is not receipt membership')
        if checks['batch']['status'] == 'match' and proof['network'] == 'mainnet':
            text = batch.canonical({'version': batch.VERSION, 'network': 'mainnet', 'count': proof['count'], 'commitment': batch_commitment})
            derived = core.digest(text)
            binding = check('match' if commitment is None or commitment == derived else 'mismatch',
                            'SHA256(publisher text) derived from independently checked batch proof and caller commitment')
            expected = derived
        details = inclusion.verify({k: v for k, v in sidecar.items() if k != 'version'}, expected, expected_txid)
        details['commitment_binding'] = binding
        details['header_anchor'] = check('unchecked', 'no caller-selected header hash')
        if trusted_header is not None:
            core.h(trusted_header)
            if 'header_hash' in details:
                details['header_anchor'] = check('match' if trusted_header == details['header_hash'] else 'mismatch',
                                                 'caller-selected header only; no selected-chain validation')
        publication = {k: details[k] for k in ('publication_plan', 'submission', 'provider_report')}
        checks['publication'] = check('unchecked' if any(x['status'] == 'unchecked' for x in publication.values()) else 'missing',
                                      'publication assertions never establish inclusion', checks=publication)
        status = 'missing' if 'raw_tx_hex' not in sidecar else 'mismatch' if any(type(x) is dict and x.get('status') == 'mismatch' for x in details.values()) else 'unchecked'
        checks['inclusion'] = check(status, 'offline arithmetic only; selected-chain validation always unchecked, never SPV', checks=details)
    return {'report_format': REPORT, 'adapter': ADAPTER,
            'receipt_digest': report['receipt_digest'], 'results': checks,
            'source_authentication': report['source_authentication']}


def build_batch(receipts, *, nonces, network='mainnet', export_private_proofs=False, workflow_id=None):
    """Validate completed core receipts, then hash exact canonical complete bytes.

    Never calls mainnet prepare, funding, signing, grants or submission. Optional
    publication_request is inert; existing frozen quote and approvals still apply.
    """
    if type(receipts) is not list or not 1 <= len(receipts) <= batch.MAX_LEAVES:
        raise core.Invalid('bounded ordered receipt list required')
    entries = []
    total = 0
    for item in receipts:
        if type(item) not in (tuple, list) or len(item) != 2:
            raise core.Invalid('receipt ID and bundle required')
        rid, bundle = item
        if type(bundle) is not dict or bundle.get('version') != 'hermes-receipt/v1':
            raise core.Invalid('completed hermes-receipt/v1 required')
        if core.verify(bundle)['evidence_chain']['status'] != 'match':
            raise core.Invalid('invalid receipt hash chain')
        raw = core.contract_canonical(bundle)
        total += len(raw)
        if total > batch.MAX_BATCH_BYTES:
            raise core.Invalid('batch byte budget')
        entries.append((rid, raw))
    result = batch.build_batch(entries, nonces=nonces, network=network, export_private_proofs=export_private_proofs)
    if workflow_id is not None:
        result['publication_request'] = batch.commitment_request(result['manifest'], workflow_id=workflow_id)
    return result
