# Verification and acceptance boundary

Runtime and test framework are standard-library-only. The native smoke additionally needs an installed compatible Hermes environment. Actual compatibility was exercised with Hermes revision `fda9fb75b4ad2f641cdcf56fdfb13fbf581705ac` and Python3.11.15; host-independent tests also ran on Python3.9.6. No claim covers every host release or Windows/macOS/Linux filesystem race model.

## Development evidence

- Original base15, identity20, assurance20 and integrations21 tests replayed successfully from preserved copies with host dependencies. Zero skips in those original runs. The first integrations capture omitted a packaging LICENSE input; the corrected supplemental capture and replay passed, without changing staging source.
- Integrated source suite:70 tests passed, zero skips with host dependencies. Host-independent run:69 passed and1 native-host test explicitly skipped. A skip never counts as native acceptance.
- Actual Doctor/default registration, real PluginContext/configuration, `registry.dispatch` JSON-string ABI,6defaults and19all-groups tool names, valid/invalid calls for every tool, and3actual registered skill paths are covered by `scripts/native_smoke.py`.
- TDD receipts retain failures then passes for six-default assembly, optional groups/capability reporting/collisions, early budgets/schema types, four F1 boolean/float substitutions, batch private-proof output policy, installer behavior, native skill/composite smoke and source-manifest creation.
- Original domain/preimage tests remain, plus independent Merkle/index/count/network and second-chain-link fixtures,27gate-invalid cases, nonce/redaction/receipt-tamper checks and explicit `ok:true`/comparison-false controls.

Raw evidence and source transformations live outside shipping inventory. A prior original native smoke used direct handlers; the consolidated native acceptance uses **scoped registry.dispatch**, not only handlers/facade doubles. No assembly-shell capture facade is used.

## Reproduce on reviewed source

```sh
python -m unittest discover -s tests -v
python scripts/update_manifest.py --check
python scripts/native_smoke.py .
```

Run the last command with the Hermes dependency interpreter. Use an explicit temporary HOME/HERMES_HOME when invoking host CLI help or Doctor; never point tests at the live profile. The smoke creates its own isolated host configuration and blocks outbound socket connects, but is not an OS sandbox.

## Artifact acceptance checklist

1. Regenerate canonical source inventory only after reviewed changes. Record its separate SHA256; it excludes its own bytes. Never embed a changing report's hash in itself.
2. Build fresh wheel/sdist with already-installed setuptools. Audit inventories: one native manifest/entry, all three skills, no verification trees, credentials, machine paths, extra plugin manifests, archives or links/traversal. Generated package metadata is audited separately from source hashes.
3. Extract sdist outside the checkout. Recheck manifest hashes. Exercise installer dry-run and explicit install into an existing temporary synthetic profile; verify config unchanged and collisions refused. Read back installed hashes.
4. Run full tests and native smoke against that installed directory, with source absent from import paths. Confirm default6 and optional19 dispatch, three installed skill paths, errors and negative comparisons.
5. Install wheel with `pip install --no-index --no-deps` into a clean temporary venv; run pure domain/adapter suites outside checkout and confirm imports resolve to site-packages. Wheel is a library, not native placement. Rebuild wheel from sdist as an additional packaging check.
6. Keep exact commands, interpreter/version, host revision, exit codes, source-manifest hash and artifact hashes in a separate local receipt. Final parent review verifies those bytes before any release decision.

## What is not verified or approved

No live profile activation, actual private persona/config/session reading, wallet access, chain/network requests, authentication/signatures, transactions, spending, deployment, upload, commit or publication. No SDK/BRC/BEEF/BUMP/SPV/PoW/chain-selection conformance, human consent or production logging/privacy certification. Public-chain/newer protocol/UI packs are not included. Independent final integrated review, public owner/visibility/attribution and license approval remain outstanding.
