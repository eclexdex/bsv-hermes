# Receipt bundle contract 1

Status: core v1; reference implementation in `bsv_hermes.receipts.contract`. Independent checker in `bsv_hermes.receipts.verifier`. No Hermes, wallet, network or cryptography package required for the core. Product adapters/budgets and CLI are in [RECEIPTS.md](RECEIPTS.md).

Canonical JSON C(x): UTF-8 JSON, sorted ASCII object keys, no whitespace, ensure_ascii=True, no floats; values restricted to null, bool, safe integers (absolute value <= 9007199254740991), strings without surrogates, lists and objects with ASCII keys. No Unicode normalization. Duplicate JSON keys rejected. Strings use Python JSON escaping (including lowercase hex Unicode escapes). JSON parsing rejects NaN/Infinity.

H(label,x) = lowercase hex SHA256(ASCII('hermes-receipt/v1/' + label) || byte 0 || C(x)). Raw content D(bytes)=SHA256(bytes). Contents are arbitrary bytes, never implicitly decoded or normalized.

Bundle exact fields: version='hermes-receipt/v1', instruction (content descriptor), approved_inputs (ordered descriptors), tools (ordered records), final_output (descriptor), receipt_digest. Descriptor exact fields: name (nonempty string), sha256 (64 lowercase hex), size (nonnegative safe integer). Approval is caller-declared scope, NOT authenticated user approval.

Tool record exact fields: index (zero-based contiguous integer), tool (nonempty string), request (descriptor), response (descriptor), previous (prior event_digest or H('start', {instruction,approved_inputs})), event_digest = H('tool', record without event_digest). Order is significant. All descriptors must have unique names across the entire bundle. Final receipt_digest = H('bundle', bundle without receipt_digest). Empty tool list allowed. These exact preimages bind instruction, declared approved inputs, ordered request/response evidence, and final output.

Content verification requires an explicit name->bytes artifact map. Missing artifacts are unverified, not successful content verification. Extra artifact names rejected. A changed payload cannot pass if bytes are supplied; absence of bytes cannot authenticate content.

Verification results are separate from the bundle: artifact, chain, signature, batch, inclusion are ALWAYS separate dimensions. chain here is local hash-chain integrity, not blockchain inclusion. Signature, batch and inclusion remain unverified_source unless explicit external adapters supply evidence; v1 has no such adapters and does not accept their assertions inside a bundle. A valid digest is not authenticated execution, human approval, signature, chain publication, batch membership or inclusion. Synthetic fixtures only; no public receipt or txid is asserted.

Product CLI: `python -m bsv_hermes.receipts verify bundle.json`. Exit 0 means report produced, never execution truth or an overall verification verdict; exit 2 means invalid input/output. Unknown fields and unsupported versions reject. Signatures, batching and inclusion remain external to this immutable core under the explicitly versioned adapter documented in RECEIPTS.md. The core alone assumes no optional crypto availability.
