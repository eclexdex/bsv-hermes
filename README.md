# bsv-hermes — provisional, unpublished

One Hermes-native directory plugin, one `bsv` toolset, one Python distribution. Six offline defaults plus three explicitly opt-in groups. Runtime dependencies: Python standard library only. No wallet, signing, network, payment or publication tools.

## Easy local installation

Review source and [license policy](LICENSE-POLICY.md). Public owner/license are pending; these artifacts are not release approval. Use the source checkout or extract the **source distribution**, not the library wheel.

From that source root, with an **existing, explicit absolute profile directory**:

```sh
python scripts/install_local.py --profile /absolute/path/to/profile
```

This is a dry-run: verifies the canonical source inventory and each hash, rejects unsafe links/traversal/collisions, and writes nothing. To actually copy the reviewed files:

```sh
python scripts/install_local.py --profile /absolute/path/to/profile --install
```

It creates only `<profile>/plugins/bsv-hermes`, reads it back, refuses overwrite and **does not edit config, enable anything, fetch dependencies or use Git/network**. It never infers your home/profile. A future upgrade needs a separately reviewed removal/migration; this installer has no force flag. Only run against a trusted local filesystem without concurrent writers to the target ancestors.

Then explicitly select the same profile and approve activation yourself. POSIX shells:

```sh
export HERMES_HOME=/absolute/path/to/profile
hermes plugins doctor "$HERMES_HOME/plugins/bsv-hermes"
hermes plugins enable bsv-hermes
```

PowerShell: set `$env:HERMES_HOME = 'C:\absolute\profile'`, then run the same `hermes plugins enable bsv-hermes` command. Restart Hermes or use `/reset` to refresh tools/skills. `hermes plugins install .` is **not** this local directory installation route: current CLI install accepts catalog/Git identifiers. No approved Git repository identifier exists yet.

The wheel is a **library + packaged skills**, not an automatic native plugin install. Native discovery uses the root `plugin.yaml` and root `register(ctx)` entry in the source distribution; no untested entry-point requirement is invented.

## Default tools

| Tool | Supplied input and result |
|---|---|
| `bsv_capabilities` | `{}` → actual registered names and enabled groups |
| `bsv_inspect_transaction` | Legacy transaction hex → bounded structural summary/txid |
| `bsv_inspect_script` | Script hex → inert disassembly, never execution |
| `bsv_plan_commitment` | Exact UTF-8 text → unsigned SHA256 OP_RETURN script plan |
| `bsv_identity_soul` | Exact supplied bytes as base64 + network → versioned SOUL commitment/receipt comparison |
| `bsv_assurance_artifact` | Supplied digest/byte-count records + network/nonce → workproduct digest receipt |

Examples: `bsv_plan_commitment({"text":"hello"})` and `bsv_identity_soul({"data_b64":"aGVsbG8=","network":"testnet"})`. These produce **different formats on purpose**. No home SOUL or file content is discovered automatically.

Native results are JSON strings: `{"ok":true,"result":...}` (optional `warnings`) or `{"ok":false,"error":{"code":"invalid_input","message":"..."}}`. **Execution success is not comparison success**: `result.matches`, `digest_match`, `evidence_ready`, or the boolean `result` of batch verification may be false. Inspect them separately.

## Optional groups — same install, default disabled

Explicit operator configuration under the chosen profile's native plugin settings:

```yaml
plugins:
  entries:
    bsv-hermes:
      settings:
        enabled_kits: [identity, assurance, integrations]
```

Choose any subset; unknown/duplicate values reject registration. Restart to apply. This repository never writes that setting itself.

- **identity**: `bsv_identity_instructions`, `bsv_identity_posture`, `bsv_identity_release` (three additional tools).
- **assurance**: `bsv_assurance_tool_chain`, `bsv_assurance_deployment_gate`, `bsv_assurance_approval_intent` (three additional tools, strictly advisory).
- **integrations**: `bsv_int_batch`, `bsv_int_verify_batch`, `bsv_int_content`, `bsv_int_overlay`, `bsv_int_handoff`, `bsv_int_chain`, `bsv_int_reconcile` (seven additional tools, all offline).

With all groups there are 19 tools, still one toolset. Doctor's fresh sandbox checks the six default declarations; the native smoke additionally loads all groups through real synthetic profile configuration and dispatches all 19. Public-chain transport, newer proof/UHRP codec/quote/scaffold/index packs and visual builders are **staged elsewhere, not shipped or registered here**.

## Three task skills

Use `skills_list`, then `skill_view` with `bsv-hermes:inspect-evidence`, `bsv-hermes:plan-commitment`, or `bsv-hermes:audit-workproducts`. They cover optional capabilities without adding per-tool skill clutter.

## Privacy and evidence boundaries

Native arguments are visible to the host and may enter host logs. Supply only approved nonsecret projections. Deterministic text/SOUL commitments permit guessing. Assurance and integration nonces remain caller-retained and are omitted from native results, but cannot be hidden from the invoking host.

Batch proofs are omitted by default. `export_private_proofs: true` explicitly returns them for **private local use**. Root salting does not hide proof siblings: low-entropy leaf guesses and correlation remain possible. Publish only the final commitment when hiding is required, with separate approval. No v1 hash algorithm changed to enforce this safer output boundary.

Parsing, digest equality, branch arithmetic, provider labels and supplied timestamps do not establish authorship, human consent, complete logging, execution truth, selected-chain membership, PoW, SPV, finality, spendability or deployment safety. A caller can mint a matching approval token; no authenticated authorization exists. [Contracts and exact formats](docs/CONTRACT.md) · [Security](SECURITY.md) · [Provenance](PROVENANCE.md).

## Verify and develop

```sh
python -m unittest discover -s tests -v
python scripts/update_manifest.py --check
```

The host-independent suite explicitly skips its one native-host test if Hermes dependencies are absent; that is not native acceptance. For the complete native smoke, use the Python environment of an installed compatible Hermes host:

```sh
python scripts/native_smoke.py .
```

That command exercises real Doctor, PluginContext, scoped `registry.dispatch`, six defaults, all optional groups and three readable registered skills in temporary homes with socket connections blocked. It never enables the live profile. With already-installed trusted setuptools >=77, build without dependency downloads:

```sh
python -c "from setuptools.build_meta import build_wheel, build_sdist; print(build_wheel('dist')); print(build_sdist('dist'))"
```

Regenerate `SOURCE-MANIFEST.json` with `python scripts/update_manifest.py` only after reviewed source changes. Hashes detect corruption, not author authenticity. Final acceptance must repeat installation and native smoke on the extracted archive outside the checkout. See [verification](docs/VERIFICATION.md).
