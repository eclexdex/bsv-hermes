# Source provenance and inventory

This repository consolidates reviewed original prototype base, identity, assurance and integration implementations. No SDK/research source archive or third-party sample was vendored. Original source snapshots and per-file mappings/hashes are retained separately in nonshipping local verification evidence; their workstation paths and raw logs are deliberately absent here.

## Transformations

- Base `domain.py` remains byte-identical; its transaction/Script/text behavior and literal fixtures remain unchanged.
- Reviewed kit domain modules moved under `bsv_hermes/kits/{identity,assurance,integrations}`. Commitment domains, representation identifiers, canonical byte encodings and receipt versions remain unchanged.
- Standalone kit registration/manifest/distribution/CLI/skill surfaces were not transplanted. Reviewed request/schema operations are internal modules; one root adapter applies shared validation and JSON-string `ok/result/error` envelopes.
- Assurance `verify_chain` was minimally repaired: bounded canonical-byte equality replaces Python dict equality, so `true` cannot equal version1 and `0.0` cannot equal pending_count0.
- Integration v1 batch proofs remain available to the private library and explicit native private export, but native default output removes proofs and warns about guessing/correlation. Hashes are unchanged.
- Three task skills replace per-kit skills; optional identity/assurance/integration registration uses native configuration, not an incomplete capture facade.
- Candidate staged MIT metadata was not adopted because operator licensing/attribution/ownership were undecided. Immutable original evidence is not rewritten. See THIRD_PARTY.md and LICENSE-POLICY.md.

## Mainnet integration

Selected first-party wallet, funding, builder, signer, spend-policy, broadcast and
publisher components live under `bsv_hermes.mainnet`, not separate plugins or
research-path imports. Current recovered signer bytes were used rather than the
stale acceptance snapshot; its canonical wallet import was relocated. The new
coordinator reuses publisher commitment encoding and descriptor-locked journal,
then maps provider/builder/signing/policy contracts explicitly. It replaces the
unwired publisher callback surface with separate operator grants, durable
pre-custody budget locks and exact readback settlement. Generic historical
component APIs are not additional native tools or authority.

No source format/preimage from existing offline tools changed; original domain
cases remain and registration expectations include the added producer. Dependency wheels are not vendored; the opt-in extra,
platform lock and preserved notices are documented in THIRD_PARTY.md. Exact
source-input hashes, transformation mappings and baseline archive remain in the
nonshipping local verification directory.

## Receipt integration

Reviewed first-party receipt-wave modules were selected, not copied as lane trees:
core contract/golden preimages (01); independent verifier (02); producer/native
fragment (03); inactive lifecycle recorder (04); nonce-bearing batch (05);
optional Ed25519 sidecar (06, backend pin reconciled to 48.0.0); offline inclusion
(07); inert viewer (08); offline release checks/canary procedure (09); independent
adversarial corpus/harness (10). Research reports, raw results, environments and
local paths are excluded. Exact input hashes and RED/GREEN evidence are local-only.

`receipt-evidence/v2` explicitly composes canonical complete-bundle signature/batch
sidecars; it does not relabel legacy digest preimages. The checker remains separate
from the producer. Library-object preflight was added before serialization; producer
artifact sizes align with the 16 MiB verifier profile. Viewer explanations map actual
`detail` fields. Original adversarial hashes were not converted: new frozen semantic
cases target the production schema while original parser-attack bytes remain pinned.

Confirmed low audit repairs: reject ambiguous/truncated funding response framing;
test component origin by package containment, not ancestor name; document legacy
finite-float canonical bytes without changing commitments; portable README image
URLs and scope wording. Broadcast Journal pins its live SQLite connection and checks
identity rather than reopening a substituted path; initial SQLite open/auxiliary
files still require a trusted directory. No hostile-directory race-proof claim.

## Canonical inventory

`SOURCE-MANIFEST.json` is UTF-8 JSON with sorted keys, compact separators and a final newline. Its `files` mapping contains SHA256 for each reviewed shipping source/test/doc/skill/helper file. It **excludes itself** to avoid recursive hash evidence. Hash the manifest separately to bind a verification run. Generation uses an explicit root-file list and allowlisted source directories; local verification, Git data, build trees, archives, bytecode and generated distribution metadata are excluded.

The installer copies only manifest-listed files plus the manifest, validates every hash and reads back the exact target. Sdist includes the native root, source manifest, test fixtures and portable helpers. Wheel includes only `bsv_hermes` modules, the self-contained receipt-viewer template, three skill resources, mainnet dependency lock/notices and standard metadata: it is a library, not automatic native installation. Build metadata generated by setuptools is outside the source manifest; archive acceptance audits it separately.

Authoritative API reference: [Hermes plugin guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/). The runtime imports no host internals. The development smoke uses the real host's version-sensitive Doctor sandbox, PluginContext registrations and scoped registry dispatch; future host versions must rerun it. Source publication to the existing GitHub repository is authorized; product license and copyright attribution remain pending.
