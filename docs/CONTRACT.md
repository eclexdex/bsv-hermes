# Unified native contract

## Authority and envelope

One root manifest/entry point, one distribution/namespace `bsv_hermes`, one native toolset `bsv`. Handlers accept an object, ignore extra host-context kwargs and return a JSON string. Success: `ok:true,result:<domain value>` and optional warning strings. Input rejection: `ok:false,error:{code:invalid_input,message:<fixed text>}`. No raw inputs appear in errors. `ok` means completed computation only; boolean comparisons remain separate, including a literal false `result` for batch membership.

Schemas are revalidated at the native boundary, including unknown fields, exact bool/integer distinctions and nested schemas. A shared pre-serialization guard caps native JSON at 4 MiB escaped ASCII bytes, 200000 characters per string, depth 32 and 20000 nodes; cyclic/non-JSON/non-finite/float values reject. Protocol-specific smaller budgets still apply. No input file path, URL, key or wallet parameter exists in a native tool. Native registration reads only its documented `enabled_kits` setting through the host facade and registers packaged skill paths. It installs nothing.

## Default six

- `bsv_inspect_transaction`: strict even ASCII hexadecimal `transaction_hex`, optional `max_items` integer 1–100 (default20). Maximum100000 decoded bytes,1000 inputs/outputs,10000 bytes per script. Noncanonical CompactSize, empty vectors, truncation, trailing bytes and witness marker serialization reject as parser policy. Txid is reversed double-SHA256. No fee without prevouts.
- `bsv_inspect_script`: strict `script_hex`, maximum10000 decoded bytes; same display bound. Direct pushes/PUSHDATA1/2/4 parsed completely even if preview truncates; data previews32bytes. Unknown opcode names are partial, not consensus judgments.
- `bsv_plan_commitment`: maximum4096 exact UTF-8 bytes from `text`. Locking script is `006a20 || SHA256(text UTF-8)`;35bytes. No normalization, purpose/network separation, nonce, transaction, funding or submission.
- `bsv_identity_soul`: exact supplied `data_b64` maximum65536 decoded bytes and explicit `network` (`mainnet`/`testnet`). Optional object `receipt` requests exact receipt comparison; malformed scalar receipt rejects, well-typed unmatched object yields `matches:false`. No private-opening input in this native surface.
- `bsv_assurance_artifact`: `evidence` with network,1–128 ordered items of lowercase32-byte `digest` and exact nonnegative `bytes` integer, and32-byte lowercase nonce. It commits supplied claims, not artifact bytes read from disk. Public result omits projection and nonce.
- `bsv_capabilities`: empty object → names successfully registered by this instance, actual configured groups, available groups and false network/signing/payments/broadcast flags. No roadmap entries masquerade as availability.

## Preserved formats, not interchangeable algorithms

| Format | Preimage semantics retained |
|---|---|
| Base text plan | Plain SHA256 of exact UTF-8, no network/domain |
| Identity v1 | SHA256(uint32be(header length) || canonical ASCII header || exact bytes); header domain `bsv-hermes-identity/v1`, kind, network, representation `exact-bytes-v1`, nonce |
| Identity manifests | `sorted-file-sha256-v1`, sorted safe supplied names/byte-counts/SHA256; posture uses `non-secret-posture-v1` exact allowlisted fields |
| Assurance v1 | SHA256(`hermes-assurance/v1` + NUL + purpose + NUL + bounded sorted ASCII JSON projection); chain links bind prior link, event, index, network, nonce |
| Custom batch v1 | Domain `bsv-hermes/merkle-batch/v1`; index-prefixed0x00 leaves,0x01 pair nodes, duplicate-last odd rows,0x02 outer count/root/network/nonce commitment |
| Integration envelopes v1 | SHA256(`bsv-hermes/evidence-envelope/v1` + NUL + sorted ASCII JSON); overlay/handoff carry distinct domains |
| Raw chain arithmetic | Double-SHA256 and Bitcoin display-endian comparisons of supplied bytes/branch/header; **no transaction parsing or chain trust** |

Canonical profiles use sorted keys, compact separators, ASCII escaping, no Unicode normalization and no NaN. They are bespoke versioned profiles, not JCS. Domain libraries retain their original schemas/budgets; common native validation does not rewrite their bytes. Assurance `verify_chain` now compares bounded canonical receipt bytes rather than Python dict equality, rejecting bool/float substitutions without changing any commitment.

## Optional groups

`enabled_kits` is an explicit list selected via `plugins.entries.bsv-hermes.settings.enabled_kits`. Default empty. Unknown/duplicate/non-string entries fail closed. All optional registrations use the real native facade and `override:false`; conflict failures dispose prior registration handles.

Identity adds instruction-manifest, nonsecret-posture and release-manifest tools. Assurance adds supplied tool chains, advisory deployment gate and unauthenticated approval-intent comparison. Integrations adds custom batch create/verify, supplied content comparison, overlay/handoff receipts, raw chain arithmetic and receipt-claim reconciliation. Schemas in the registry are the exact parameter contract.

Batch native output omits `proofs` unless exact boolean `export_private_proofs:true`. This removes a public leakage surface but does not alter the v1 root/commitment or private library proof format. Returned proofs remain guessable/linkable. No public/private guarantees can override host logging of supplied nonce arguments.

Assurance native results intentionally omit private projections/chain links. For local gate preparation, retain approved input projections and call `bsv_hermes.kits.assurance.core.artifact(projection)` / `chain(projection)` in a separately controlled local workflow to obtain full receipts. Native redacted outputs alone are not full gate inputs; never invent missing evidence. Identity's historical file helpers remain library-only, POSIX-oriented and unregistered; the native product only accepts supplied content. No opening-file CLI is shipped.

## Evidence vocabulary

`matches`/`digest_match`/`integrity_match`: only the named supplied bytes/receipt reconstruction. `evidence_ready`: advisory combination of supplied integrity/completeness/network/time conditions, never deployment permission. `evidence_matches`: caller-token match, no authenticated human consent or durable replay protection. Null means unavailable/unperformed, not false and not verified. Parsing, arbitrary matching headers and custom batch membership do not establish SPV, PoW, selected-chain ancestry, confirmations, content truth or legal admissibility.
