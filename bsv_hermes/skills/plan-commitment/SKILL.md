---
name: plan-commitment
description: Create supplied-content commitments without custody.
version: 0.2.0
author: Human attribution pending; Hermes Agent collaborator
license: Pending operator decision
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bsv, offline, supplied-evidence]
---

# plan-commitment

## When to Use
Use to create an unsigned text or supplied SOUL commitment, and optional identity manifests or Merkle batches. Never auto-read a home SOUL, config, session or wallet.

## Prerequisites
Reviewed plugin enabled. Inputs must be explicitly supplied, approved nonsecret content. Native inputs may be visible in host logs.

## Procedure
1. Call `bsv_capabilities`. Choose the representation: `bsv_plan_commitment` hashes exact UTF-8 `text` (maximum 4096 bytes), while `bsv_identity_soul` accepts `data_b64` (maximum 65536 decoded exact bytes) plus explicit `network` mainnet/testnet.
2. Preserve bytes: no Unicode/whitespace normalization or line-ending changes. The text tool returns `006a20` plus plain SHA256; identity uses the distinct versioned purpose/network-bound preimage. They are not equivalent commitments.
3. For a SOUL receipt comparison, supply its public `receipt` with the same bytes/network. Check `result.matches` separately from `ok`. Native identity commitments are deterministic and do not provide private openings.
4. If enabled, identity instruction/release tools accept explicit supplied file entries, never a filesystem root. Posture accepts only its nonsecret fields. Integration batch accepts digests/network/nonce and omits proofs by default.
5. Keep all receipts local unless separately approved for publication. A batch `export_private_proofs: true` is an explicit private export, not consent to publish. Proofs reveal guessable/linkable leaf fingerprints even when the final commitment is salted.

## Pitfalls
No transaction is built, signed, paid or submitted. Digests of low-entropy data permit guesses; native nonce arguments also enter the host's input boundary. Do not claim that root salting hides exported proofs, or that a network label proves chain membership.

## Verification
Require `ok: true`; check representation, domain, network and unchanged receipt version. For comparisons require the separate match field. Report publication as unsigned/not submitted and authorship as unestablished. Never present a digest as proof of consent or content truth.
