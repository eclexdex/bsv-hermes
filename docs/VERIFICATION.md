# Verification and acceptance boundary

The base/default and three offline kits remain dependency-free. Original domain
cases are retained; registration counts include the new receipt producer. Crypto tests use a separate environment
with bsv-sdk 2.4.0 and cryptography 48.0.0; no real wallet, operator credential,
private SOUL, public POST or funded spend is permitted in this acceptance path.

## Reproduce

```sh
# Host-independent/default suite; inspect skips rather than counting them as passes.
python -m unittest discover -s tests -v
python scripts/update_manifest.py --check

# Use the compatible Hermes host interpreter for these native checks.
python scripts/native_smoke.py .
python scripts/mainnet_smoke.py . --sdk-python /absolute/pinned-sdk-venv/bin/python

# Exercise real crypto tests with the isolated SDK environment itself.
/absolute/pinned-sdk-venv/bin/python -m unittest discover -s tests -v
```

For a Hermes source checkout, make its source importable, for example with an
explicit `PYTHONPATH` while invoking the host's dependency interpreter. Do not
point test HOME/HERMES_HOME at a live profile. Scripts use temporary synthetic
homes; temporary directories should be directed to a trusted local scratch root.
Missing Hermes explicitly skips the host case; missing **exact** SDK pins skips
mainnet cases. A skipped case never establishes acceptance.

## What is exercised

- Actual Plugin Doctor, PluginContext registration and scoped `registry.dispatch`
  JSON-string ABI; not only direct handlers or registration doubles.
- Six defaults and twenty tools with the three offline groups; three actual
  registered skill paths. The separate mainnet smoke verifies fourteen tools
  (six defaults plus eight mainnet), valid dispatch for every added tool and
  invalid/spoofed fields rejected before runtime work.
- Native subprocess crossing into the isolated SDK interpreter, real fresh
  never-funded key creation, funding observation mapping, real builder/signature
  computation and independent PyCA verification. No fake signature or invented
  production adapter result substitutes for missing dependencies.
- Separate operator-only signed grants and exact plan/txid binding; aggregate
  outstanding budget/input locks claimed before custody; corrupted/forged grants,
  revocation, stale inputs, changed signed bytes and concurrent callers.
- Real loopback HTTP submission and exact txid/raw transaction readback, delayed
  observation, ambiguous outcomes, lost signing results and crash-after-dispatch.
  Locks remain held and repeated calls do not resend. The provider/ancestry are
  explicitly synthetic. This is transport/software evidence, not chain success.
- Default import/registration is offline. Test transport injection lives in the
  harness, not runtime configuration or caller-selectable arguments.

The single combined mainnet native smoke runs real isolated workers with trusted
test-only loopback adapters. The unmodified shipped worker is also exercised by
SDK tests for wallet/status/error calls. The native API never accepts a backend
factory/module, loopback URL, authority path, key, grant or arbitrary script.

## Distribution acceptance

1. Preserve baseline source/test output. Rehash final selected source inputs,
   including current signer bytes rather than stale acceptance snapshots.
2. Refresh `SOURCE-MANIFEST.json` only after reviewed edits. Its sorted compact
   JSON maps every shipping source/test/doc/helper/resource file except itself;
   bind its own SHA256 separately. Hashes detect drift, not author authenticity.
3. Build fresh wheel and sdist with reviewed tooling. Inspect all archive members:
   one native root/manifest in the sdist, three skills and mainnet lock/notices,
   exact direct dependency pins, no extra plugin, links, traversal, private paths,
   wallet/authority files, grants, databases, verification logs, build environments,
   upstream archives or SDK binaries.
4. Extract the sdist outside the checkout. Recheck its manifest and install via the
   explicit local installer into an existing synthetic profile. Verify dry-run,
   no config mutation, no overwrite and exact installed hashes.
5. Repeat actual Doctor/default and mainnet registry dispatch, skill discovery,
   source tests and crypto tests on extracted/installed bytes with the original
   source absent from import paths. Wheel installation alone is not native-plugin
   acceptance.
6. Install the wheel in a fresh environment, check `site-packages` origin and all
   resources, run library/worker checks outside the checkout and rebuild from the
   extracted source. Keep direct SDK and Hermes dependencies isolated.
7. Preserve exact commands, return codes, full stdout/stderr, source and archive
   hashes in ignored local receipts. The parent owns independent final review,
   staging, commit and any later push. No build script performs those operations.

The project CI currently covers the dependency-free suite and clean base wheel;
it does not certify mainnet crypto/platform compatibility. The mainnet native
smoke and isolated SDK suite must be run explicitly for a release candidate.

## Receipt release acceptance

Use an explicitly trusted, **symlink-free TMPDIR**, especially on macOS where
`/var` is a symlink. No custody path protection is weakened to make a smoke pass:

```sh
mkdir -p local-verification/receipt-tmp
export TMPDIR="$(python -c 'from pathlib import Path; print(Path("local-verification/receipt-tmp").resolve())')"
python -m unittest discover -s tests -v
python scripts/receipt_adversarial.py --output local-verification/adversarial.json
python scripts/receipt_mutations.py --output local-verification/mutations.json
python scripts/update_manifest.py --check
```

Use the host interpreter/source for `scripts/receipt_host_smoke.py .`: actual
gateway HookRegistry discovery and emit, unarmed no-write, canary exclusion and
receipt input integration in a synthetic HOME. No live hooks or model run.
`native_smoke.py` passes actual script-dispatch return bytes through the native
run producer and independent checker. `mainnet_smoke.py` now prepares the exact
batch publisher text through the existing independent sign/submit workflow.

With reviewed setuptools >=77 and wheel already installed, run one full offline
package gate (choose a **new** output directory; substitute actual interpreter paths):

```sh
python scripts/receipt_release_check.py --out local-verification/receipt-release \
  --hermes-python /absolute/hermes-venv/bin/python \
  --hermes-source /absolute/hermes-agent \
  --sdk-python /absolute/pinned-sdk-venv/bin/python \
  --browser-python /absolute/browser-test-python
```

This snapshots exact manifest-listed source, scans sources/archives, builds wheels
twice, rebuilds a byte-identical wheel from sdist, installs both wheels offline in
fresh venvs and runs the actual verifier/CLI/resources/tests outside the checkout.
Those venvs have no Hermes, wallet SDK or crypto. Missing optional crypto returns
unchecked, with explicit suite skips. The separate pinned SDK suite exercises
positive signatures/RFC8032 and real mainnet software adapters. Extracted native
install readback, Doctor/dispatch/skills, lifecycle hook tests, synthetic mainnet
batch flow and actual browser tests follow when the optional harness paths are
supplied. Omitted host/browser gates are reported as skips, not passes.

`RESULTS.json` retains exact commands, exits, source and archive hashes, inventories
and skip reasons. Wheel reproducibility is tested; sdist gzip/tar reproducibility
is not claimed. The lane10 harness uses independently pinned production semantic
translations, not reinterpretation of its draft hashes. The mutation runner resets
between mutants and verifies imported mutated paths/hashes before assertion kills.
The viewer's screenshot inspection is separate from DOM/network assertions.

## Not certified or approved

No funded/public-provider submission, trusted-chain inclusion/SPV/consensus,
mainnet fee acceptance, production broker isolation, human authentication channel,
private-backup policy, power-loss/rollback resistance, cross-platform custody or
complete SDK security audit is claimed. Same-UID file/shell access defeats the
operator boundary. Crashes between journal/ledger writes can strand availability
and require trusted reconciliation, never reset/refund. No live configuration,
Git staging/commit/push, release license selection or publication is performed by
this verification workflow. See [MAINNET.md](MAINNET.md) and [SECURITY.md](../SECURITY.md).
