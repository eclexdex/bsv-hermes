---
name: audit-workproducts
description: Audit workproduct and deployment evidence locally.
version: 0.2.0
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

## Pitfalls
A self-consistent recomputed history can omit events. Detect changes only against an independently retained trusted head; no complete logging or execution truth is established. A schema-invalid receipt is an input error; well-formed insufficient evidence may return `ok: true` with `evidence_ready: false`.

## Verification
Require the execution envelope to succeed, then report individual evidence fields and all unknown layers. Record failures without echoing private projections. Stop before deployment, spend, publication, authentication or live profile changes.
