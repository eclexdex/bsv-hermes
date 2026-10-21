---
name: audit-workproducts
description: Audit workproduct and deployment evidence locally.
version: 0.3.0rc2
author: Human attribution pending; Hermes Agent collaborator
license: Pending operator decision
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [bsv, offline, supplied-evidence]
---

# audit-workproducts

## When to Use
Use for supplied artifact digests, tool-event chains, advisory deployment evidence and optional handoff/provenance comparisons. Not authorization, execution or production inspection.

## Prerequisites
Reviewed plugin enabled. Caller independently hashes approved artifacts using `terminal` with Python hashlib, or supplies already-reviewed digest/size records. Never infer artifacts from an agent's success statement.

## Procedure
1. Call `bsv_capabilities`. Use default `bsv_assurance_artifact` with `evidence` containing explicit network, ordered items (`digest`, integer `bytes`) and caller-retained nonce. No artifact bytes or paths are read by this tool.
2. Retain the input projection privately. The public result omits projection and nonce. A deployment-gate input needs the full local receipts, not the intentionally redacted native outputs; construct those through the documented library workflow only on approved synthetic/local projections.
3. If assurance is enabled, create `bsv_assurance_tool_chain` from supplied attempt/terminal events. Evaluate `bsv_assurance_deployment_gate` only as advisory evidence; check integrity, network, completeness and supplied timestamp separately.
4. `bsv_assurance_approval_intent` matches a caller-authored token and supplied history only. Never connect its boolean to a privileged executor: human consent is not authenticated and replay state is not durable.
5. If integrations is enabled, compare overlay/handoff/reconciliation receipts using independently expected digests. Labels/time/history remain caller claims; do not convert matching strings into authenticated peer or chain claims.
6. For a complete supplied run, use optional `bsv_assurance_run` with explicit instruction/input/tool request-response/output bytes or reviewed digests and sizes. Preserve actual order. This uses `hermes-receipt/v1`, not legacy assurance receipts. Run IDs/source labels are unbound metadata, not signed event origin.
7. Verify independently through `bsv-receipt-verify` (same distribution, no Hermes/wallet required) with exact caller-approved artifact paths and independently chosen public key/batch commitment. Report artifact, chain, signature, batch, publication and inclusion separately. Never promote provider statements or matching arbitrary headers to selected-chain inclusion.
8. `bsv-receipt batch` creates a nonce-bearing manifest and optional private proofs. Its publisher request is inert; existing frozen quote and independent sign/submit grants still apply. Do not activate the optional lifecycle recorder or infer consent. `bsv-receipt view` renders an inert local report, not a new verification.

## Pitfalls
A self-consistent recomputed history can omit events. Detect changes only against an independently retained trusted head; no complete logging or execution truth is established. A schema-invalid receipt is an input error; well-formed insufficient evidence may return `ok: true` with `evidence_ready: false`.

## Verification
Require the execution envelope to succeed, then report individual evidence fields and all unknown layers. Record failures without echoing private projections. Stop before deployment, spend, publication, authentication or live profile changes.
