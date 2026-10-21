# Receipts: independent checks, not an overall verdict

One `bsv-hermes` distribution and native plugin. The optional assurance group adds
`bsv_assurance_run`. The same wheel also provides offline `bsv-receipt` and
`bsv-receipt-verify`; neither needs Hermes, a wallet, network access or signing keys.
Python 3.9+ on POSIX is the exercised platform. No Windows no-follow claim.

## Minimal local path

From a source checkout (or after installing the wheel, replace
`python -m bsv_hermes.receipts` with `bsv-receipt`):

```sh
python -m bsv_hermes.receipts create examples/receipt-request.json --output bundle.json
python -m bsv_hermes.receipts verify bundle.json \
  --artifact instruction=examples/receipt-instruction.txt \
  --artifact output=examples/receipt-output.txt --output report.json
python -m bsv_hermes.receipts view report.json --output receipt.html
```

Open `receipt.html` locally. All paths above are explicit grants. Output files
must be new and their parent must exist. The CLI creates files 0600 with exclusive,
no-follow descriptor-relative opens; it never overwrites or discovers files from
bundle names. Names need not be paths and are never used as paths. It does not
extract archives, fetch artifacts, install crypto or activate recording.

Exit 0 means a report/output was produced, **not all evidence verified**. Exit 2
means invalid input/output and no usable report. Inspect every `results` entry:

| Dimension | What a result can establish |
|---|---|
| `artifact` | Exact granted file bytes compared with each descriptor's size and SHA256. Unprovided paths are `unchecked`; explicitly granted nonexistent files are `missing`. A missing or failing item is not hidden by other matches. |
| `chain` | Strict core receipt digest and ordered hash links. No authentic origin, completeness or execution truth. |
| `signature` | Optional caller-trusted Ed25519 signature of canonical complete bundle bytes plus domain, time interval, nonce and key fingerprint. No consent/identity assertion beyond that key. |
| `batch` | Private opening against a **caller-selected** nonce-bearing batch commitment. It is not publication or a full-batch completeness proof. |
| `publication` | Plan, submission and provider claims remain `unchecked`, never proof of inclusion. |
| `inclusion` | Raw transaction, exact OP_RETURN pushed bytes, expected txid, Merkle/header arithmetic, supplied-target PoW and optional caller header anchor, each separately reported under `checks`. Selected-chain validation always `unchecked`; the dimension can never become `match`. |

Statuses are `match`, `mismatch`, `missing`, `unchecked`. There is no aggregate
verified flag. `source_authentication` remains unchecked even with a valid signature.
The viewer is inert presentation of imported, unauthenticated reports: it does
not itself run the verifier, authenticate the report, or trust bundled keys.

## Producer and strict core

The core is exactly [`hermes-receipt/v1`](RECEIPT-CONTRACT.md). The producer accepts
explicit instruction, approved-input, ordered tool request/response and final-output
bytes as canonical base64, or explicit SHA256 plus size. It never executes tools.
The native `run_id`, tool IDs and `source` labels remain **unbound result metadata**;
`approved_inputs` means a caller-declared scope, not authenticated human approval.
Raw supplied bytes do not appear in the resulting core bundle, but names, sizes
and unsalted hashes can disclose/correlate low-entropy content. Keep them private.

The independent checker in `receipts/verifier.py` implements core preimages without
importing the producer or reference builder. Literal golden/preimage vectors are
retained in `tests/receipt_vectors/contract`. Canonical JSON sorts ASCII keys,
uses compact separators and ASCII escapes, preserves Unicode values without
normalization, and forbids floats/nonfinite/unsafe integers. This is not JCS.
The structural JSON schema alone does not verify any digest.

Product profile: wire JSON at most 1 MiB, depth 24, 20,000 nodes, 1,024 members;
conservative pre-serialization escaped-size budget also applies to library objects.
Artifacts at most 16 MiB each; producer permits 128 inputs/tools, depth 16 and a
smaller conservative object budget. Parser refusals are not silent truncation.
File reads cover bytes actually read, not an atomic filesystem snapshot. POSIX
symlink ancestors/leaves, special files and oversized reads are rejected.
Traversal components (`..`) are rejected before normalization so explicit grants
cannot erase a symlink component. Output paths follow the same rule.

## Explicit v2 composition; no hash reinterpretation

External evidence never adds fields to the strict core:

```json
{"adapter":"bsv-hermes/receipt-evidence/v2","bundle":{},"signature":{},"batch":{},"inclusion":{}}
```

Each optional sidecar may be omitted. Empty objects above are placeholders, not
valid proofs. Unknown envelope versions/fields are rejected. Use `evidence.verify`:

```python
from bsv_hermes.receipts.evidence import verify
report = verify(envelope, {"output": explicitly_approved_path},
                trusted_key=caller_public_key_hex, now=caller_unix_seconds,
                batch_commitment=caller_commitment_hex,
                expected_txid=caller_txid, trusted_header=caller_header_hash)
```

### Signature

Sidecar fields: `version:1`, `domain:"bsv-hermes/receipt-signature/v1"`,
`algorithm:"Ed25519"`, `public_key_sha256`, `bundle_sha256`, integer `issued_at`,
integer `expires_at`, 16-byte lowercase-hex `nonce`, canonical base64 `signature`.
`bundle_sha256 = SHA256(C(complete core including receipt_digest))`.
Signed message is ASCII(domain) + NUL + C(sidecar without signature).
That hash is **not** the domain-separated core `receipt_digest`.

Caller public key is raw 32-byte lowercase hex. Its SHA256 fingerprint is checked,
never selected from a bundle. `--now` is explicit trusted caller time; validity is
`[issued_at, expires_at)`. Optional `receipt-signature` extra pins PyCA
`cryptography==48.0.0`, matching the existing mainnet pin. No pure-Python fallback.
Unavailable/wrong-version crypto yields `unchecked`, not pass. Do not alter Hermes'
crypto environment; use a separate verifier venv. The independently versioned
legacy checker uses its original direct Ed25519 backend; v2 enforces the pin.

No production receipt signer or model-callable key API is supplied. The library's
`sign_synthetic` helper is explicitly test-only and accepts only synthetic key
references. No private key is bundled. RFC8032 public test seeds live only in
clearly labeled tests. A signature is not an approval grant or signed event witness.
Replay is `unchecked` by the composed verifier; low-level signature verification can
compare a caller token set but cannot atomically consume it. Persistent atomic replay
prevention and authenticated consent UI are not implemented.

### Deterministic batches and the existing approval path

`evidence.build_batch([(id, bundle), ...], nonces=[...], network='mainnet',
export_private_proofs=False, workflow_id=None)` independently validates each core,
then hashes **exact canonical complete bundle bytes**. Every nonce must be explicit,
32-byte lowercase hex; use independently random fresh production nonces and never
reuse them. The library rejects duplicate IDs/nonces and bounds 1,024 leaves,
1 MiB per receipt and 8 MiB total. It does not prove nonce entropy/freshness.

Domain `bsv-hermes-receipt-batch/1`: H(tag,x) is
SHA256(ASCII(domain+'/'+tag) + NUL + C(x)). Leaves are
H('leaf',{receipt_id,receipt_sha256,nonce_hex}); nodes H('node',[left,right]);
ordered adjacent pairs, odd duplicate last; commitment H('commitment',{root,count,network}).
Proofs contain version, receipt_id, receipt_sha256, nonce_hex, index, count, network,
bottom-up siblings. Exact geometry, duplicated tails and count/network are checked.
Public manifest omits IDs, openings and leaf hashes. Private proofs require explicit
export; they reveal receipt fingerprints and must not be treated as public consent.

CLI `batch` takes `{receipts:[{id,bundle,nonce},...],network:"mainnet"}`;
`--export-private-proofs` explicitly exports; `--workflow-id` adds an **inert**
`publication_request`. No publisher, grant, funding, signing or submission is called.
The request's `arguments` map directly to existing `bsv_publish_prepare`.

Publisher text is C({version,network,count,commitment}); the existing publisher
commits SHA256(UTF8(text)) in `006a20 || outer_digest`. It does **not** publish the
inner commitment or root directly. The verifier derives this outer digest only
from a successful proof against a caller-selected commitment and mainnet network.
Independent frozen quote, spend limits, approve-sign and separate approve-submit
remain mandatory. Approval renewal remains unsupported; no bypass/retry was added.

### Inclusion

Sidecar version `bsv-hermes/publication-evidence/v1` permits `raw_tx_hex`,
`header_hex` (80 bytes), `merkle_path:{index,siblings}`, and untrusted `plan`,
`submitted`, `provider_report`. Siblings are Bitcoin display-order hashes, bottom-up.
The legacy non-SegWit parser requires canonical CompactSize and full consumption.
Exact complete OP_RETURN/OP_FALSE OP_RETURN data pushes are compared, never substrings.
No general script/prevout/consensus verification is implied. Arbitrary Merkle paths
lack a proven leaf count and retain Bitcoin duplicate-tail ambiguity.

`--commitment` alone compares caller-expected payload, **not receipt binding**.
`commitment_binding` stays unchecked unless derived from a verified mainnet batch.
An arbitrary matching header or its self-declared nBits is not a validated selected
chain. No consensus difficulty schedule, cumulative-work selection, confirmations,
spendability, freshness or chain timestamp evidence is implemented. No SPV claim.

### Retained independent draft API

`receipts.verifier.verify` also retains explicit `independent-v1` and
`hermes-receipt/v1-external-v1` formats for frozen independent vectors. The legacy
signature message is `hermes-independent-signature-v1` + NUL + raw core digest;
legacy batch uses 0x00-prefixed digest leaves and 0x01-prefixed binary pairs.
These are NOT v2 signature/batch formats. Legacy inclusion field names are `rawtx`,
`txid`, `header`, `index`, `siblings`. The composed CLI rejects those envelopes
rather than converting hashes or stripping nonces. Use the explicit low-level API
only when that exact old protocol is intended.

## Opt-in lifecycle metadata recorder: off by default

`receipts.gateway_adapter` has no import-time writes or registration. The shipped
plugin declares zero hooks and the installer never creates a gateway hook directory.
Do not activate it to run tests. `scripts/receipt_host_smoke.py` uses the actual
HookRegistry only inside a synthetic HOME and blocks sockets.

A separately reviewed host controller may call `arm(path, consent=True,
session_id=..., events=[...], fields=[])` before **each** run and `disarm()` in
`finally`. This boolean is a host assertion, not authenticated human consent. The
API is not model-callable. One armed run per handler instance; no concurrency UI.
Only agent:start/step/end and optional bounded integer iteration can be retained.
No prompts, responses, tool names/arguments/results, credentials, paths or session IDs
are persisted or hashed. Allowlisting happens before serialization/digest; this
does not control Hermes' own logging or session stores.

Defaults: 1,000 events / 256 KiB / 300 seconds; hard ceilings 10,000 / 1 MiB / 3,600.
Deadline is checked at callbacks, not by a background timer. Caller must disarm idle
runs. Output is new 0600; final symlinks refused; ancestors must be operator-trusted.
Partial last lines after I/O failure are possible and must fail downstream parsing.
Rows use `hermes-recorder/v1` + NUL + canonical body, **not** receipt tool preimages.
Attach finalized JSONL bytes as an explicitly approved input in a receipt; never
synthesize tool request/results from lifecycle steps. Gateway discovery/emit is
exercised; full model run, CLI/TUI/Desktop/cron hook coverage are not claimed.

## Acceptance and remaining gates

See [verification](VERIFICATION.md). Browser checks cover actual report mapping,
local imports, hostile HTML, no HTTP(S), mobile layout and controls, not WCAG
certification. Independent vectors and mutation tests cover the actual shipped
checker. Archive-attack tests do not imply a receipt ZIP importer (none exists).

Funded canary: [procedure only, NOT EXECUTED](RECEIPT-CANARY.md). Real receipt signing
with operator keys, live hooks, public broadcast, selected-chain validation and
release licensing remain explicit separate decisions or unsupported capabilities.
