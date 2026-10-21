---
name: plan-commitment
description: Plan commitments; publish only with operator authority.
version: 0.3.0rc1
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
The default planning tools build no transaction and never sign or submit. Digests of low-entropy data permit guesses; native nonce arguments also enter the host's input boundary. Do not claim that root salting hides exported proofs, or that a network label proves chain membership.

## Explicit mainnet workflow
Only when `bsv_capabilities` reports the mainnet tools and the operator has separately provisioned the dedicated runtime, use `bsv_wallet_address`, then `bsv_funding_status`. Never discover another wallet or read authority/custody files. The operator/user funds the verified address; the agent does not transfer coins.

Use `bsv_publish_prepare` with a stable `workflow_id` and explicitly approved nonsecret `text`. Show the exact quote's digest, input/change summary, fee and cost; direct the operator to the local CLI `review` for the complete frozen plan. The operator must issue a real `approve-sign` grant through their protected channel. Do not run administration via a terminal tool or treat a chat boolean/JSON approval as authority.

Call `bsv_publish_sign` only after that independent grant. It holds shared budget and inputs before custody. Show the returned final txid, then require a separate operator `approve-submit` grant. `bsv_publish_submit` is a single irreversible attempt. `bsv_publish_receipt` performs readback only; `bsv_publish_status` and `bsv_spend_policy_status` inspect local holds. Never retry, replace, cancel or clear an uncertain/signing reservation to regain budget. Missing configuration or adapters is a blocker, not a synthetic success.

`submitted` requires exact txid/raw readback and means provider observation, not consensus, mining, SPV, authorship or truth. Report any ambiguous outcome and preserved budget. No raw signed bytes or keys should enter a conversation. Separate Python interpreters do not isolate custody from same-UID terminal/file tools; production isolation is an operator prerequisite. The full ceremony and recovery limits are documented in `docs/MAINNET.md` in the native source distribution.

## Verification
Require `ok: true`; check representation, domain, network and unchanged receipt version. For comparisons require the separate match field. For offline plans report unsigned/not submitted. For mainnet report the actual stage and exact readback limits. Authorship remains unestablished. Never present a digest as proof of consent or content truth.
