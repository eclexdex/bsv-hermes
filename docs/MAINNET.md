# Mainnet digest-publication candidate

**Opt-in, bounded, independently approved. Not activated by installation.** The six
existing default tools stay offline and dependency-free. The `mainnet` group adds
eight tools to the same native plugin and `bsv` toolset. Its executable path is:

```text
operator init -> wallet address -> user funding -> provider GET observation
  -> prepare exact unsigned quote -> operator review + approve-sign
  -> reserve budget + lock inputs + begin_signing -> real SDK signing
  -> operator review exact txid + approve-submit -> durable dispatch claim
  -> one submission -> exact-txid/raw readback -> receipt + budget settlement
```

## Scope

One dedicated, newly created compressed P2PKH wallet, **BSV mainnet only**, one
`OP_FALSE OP_RETURN <SHA256(exact supplied UTF-8 text)>` zero-satoshi output and
optional change to that wallet. Maximum input text is 4096 UTF-8 bytes. Neither
SOUL discovery nor file ingestion is provided. The publisher stores only the
digest, not the text; tool arguments can still enter Hermes/model logs. A digest
of low-entropy text permits guesses. No automatic publishing, arbitrary payment,
key import/export, wallet discovery, authentication signing, 402 payments, BEEF,
SPV or generic SDK proxy is exposed.

Funding uses the reviewed bounded WhatsOnChain GET client: exact parent txid,
amount and locking script binding, confirmed/mature eligible inputs, spend-status
and repeat-list checks. This is a **single-provider observation, not consensus
or SPV**. All observed eligible inputs (at most 20) are used in a quote; no hidden
coin selection happens after approval. Newly received inputs do not change an
existing quote. Sign and submit refresh the selected inputs before proceeding.

## Dependencies and separation

Use Python 3.10+ with the separately installed `mainnet` extra:

```sh
python3.12 -m venv /absolute/dedicated-sdk-venv
/absolute/dedicated-sdk-venv/bin/python -m pip install '/absolute/extracted/bsv_hermes-0.3.0rc1[mainnet]'
/absolute/dedicated-sdk-venv/bin/python -m bsv_hermes.mainnet doctor
```

The direct pins are **bsv-sdk 2.4.0** and **cryptography 48.0.0**. The signer refuses
other versions and nonnative SDK crypto backends. Do **not** install these into an
existing Hermes environment: host crypto dependencies may conflict. The native
facade invokes a captured SDK interpreter with `-I`; it does not load SDK binaries
into Hermes. On CPython 3.12/macOS arm64 the complete reviewed environment is
[`requirements-macos-py312.txt`](../bsv_hermes/mainnet/resources/requirements-macos-py312.txt).
Install that lock with `--require-hashes --only-binary=:all:` before installing the
product with `--no-deps`. This platform-specific lock does not certify other
architectures. See [dependency policy](../THIRD_PARTY.md) and the bundled complete
[notices](../bsv_hermes/mainnet/resources/NOTICES.md). The SDK uses **Open BSV
License v4, not MIT**. No third-party SDK source/binaries are vendored here.

## Trust boundary: establish this before funding

- `init` and `approve-*` are **operator-only CLI/library operations**, not native
  tools. They do not authenticate the person running a shell. The operator must
  review the exact plan/txid in a trusted channel and protect the Ed25519
  authority directory from the model and its tools. The runtime stores only its
  public key and signed grants, never the authority private key or its path.
- The dedicated wallet is plaintext at rest. Back it up privately before funding;
  keep a small operating balance. There is no mnemonic, recovery/import feature,
  encrypted vault, hardware wallet or reliable memory zeroization.
- A separate Python interpreter **is not OS isolation**. Same-UID shell/file/code
  tools can read custody, run operator administration, replace code or roll back
  state. Deploy a trusted broker/OS boundary and authenticated operator channel
  before granting an untrusted agent access to funded execution. This repository
  has not provisioned or certified that production boundary.
- All workers must use **one runtime directory and ledger**. Never clone/reset
  ledgers to recover availability. Root/current UID and local POSIX filesystem
  integrity are trusted. Windows custody is unsupported by these no-follow APIs.

## Operator ceremony

These commands are examples for a **human operator**, not an instruction to the
agent to authorize itself. Replace every placeholder deliberately. The dedicated
runtime and authority directories must be absolute, separate, nonexistent paths
whose parents already exist and are safely owned. Nothing imports existing funds.

```sh
SDK=/absolute/dedicated-sdk-venv/bin/python
RUNTIME=/absolute/new-dedicated-runtime
AUTHORITY=/absolute/separate-operator-authority

# Operator chooses all three integer values; no default allowance exists.
"$SDK" -m bsv_hermes.mainnet init --directory "$RUNTIME" \
  --authority-directory "$AUTHORITY" --create-dedicated-wallet \
  --total-cap-sat OPERATOR_TOTAL --max-fee-sat OPERATOR_PER_TX \
  --fee-rate-sat-kb OPERATOR_RATE
"$SDK" -m bsv_hermes.mainnet address --directory "$RUNTIME"
```

Only the operator/user funds that verified address; no funding transaction is
sent by this product. `init` refuses existing or partially created directories.
Never delete a partially created wallet automatically. `doctor` inspects package
metadata only; it does not prove custody or balance readiness.

```sh
"$SDK" -m bsv_hermes.mainnet funding --directory "$RUNTIME"
# Supply only approved nonsecret text on stdin; exact bytes, no newline repair.
"$SDK" -m bsv_hermes.mainnet prepare --directory "$RUNTIME" --workflow-id first < approved-public-text.txt
"$SDK" -m bsv_hermes.mainnet review --directory "$RUNTIME" --workflow-id first
```

Review returns complete ordered inputs/source transactions, exact unsigned bytes,
output scripts/change, fee/cost and both signing/policy digests. The bare digest is
not approval. For this publication-only workflow irreversible cost equals fee.
The immutable policy caps each action, the fixed session and the entire ledger;
outstanding reservations count along with settled spending. Builder fee rate is
integer satoshis/1000 bytes, estimated conservatively at maximum signed size.
Actual-size policy bounds are from the chosen rate to twice that rate, with the
independent absolute fee cap. Change below one satoshi is rejected rather than
silently increased into fees. These are local policies, not miner acceptance.

```sh
# Operator, after examining review output; grant lasts at most five minutes.
"$SDK" -m bsv_hermes.mainnet approve-sign --directory "$RUNTIME" \
  --authority-directory "$AUTHORITY" --workflow-id first \
  --expected-digest REVIEWED_SIGNING_DIGEST --max-cost-sat OPERATOR_EXACT_CEILING
"$SDK" -m bsv_hermes.mainnet sign --directory "$RUNTIME" --workflow-id first
"$SDK" -m bsv_hermes.mainnet review --directory "$RUNTIME" --workflow-id first
# Independent second grant for the final signed txid; not implied by signing.
"$SDK" -m bsv_hermes.mainnet approve-submit --directory "$RUNTIME" \
  --authority-directory "$AUTHORITY" --workflow-id first --expected-txid REVIEWED_FINAL_TXID
"$SDK" -m bsv_hermes.mainnet submit --directory "$RUNTIME" --workflow-id first
"$SDK" -m bsv_hermes.mainnet receipt --directory "$RUNTIME" --workflow-id first
"$SDK" -m bsv_hermes.mainnet policy --directory "$RUNTIME"
```

Both the original ledger approval and submit grant must remain unexpired at
dispatch. Do not approve signing before the operator can review submission in
that window. No automatic grant renewal, refund, fee bump or reset is supported.

## Native activation (separate operator decision)

Install the existing native root using the normal dry-run/explicit installer.
After establishing the deployment boundary, the operator may select:

```yaml
plugins:
  entries:
    bsv-hermes:
      settings:
        enabled_kits: [mainnet]
        mainnet_directory: /absolute/dedicated-runtime
        mainnet_python: /absolute/dedicated-sdk-venv/bin/python
```

Registration performs no wallet/provider access. Missing settings return
`mainnet_not_configured`; missing dependencies/storage fail closed. `configured`
in capabilities means settings are present, **not** authorization/readiness.
Native calls cannot supply paths, interpreter, grants, caps, session, provider or
network. Init and approval issuance are deliberately absent.

| Tool | Arguments | Effect |
|---|---|---|
| `bsv_wallet_address` | `{}` | Exact dedicated public metadata |
| `bsv_funding_status` | `{}` | Bounded public GET observation, no funding transfer |
| `bsv_publish_prepare` | `workflow_id`, `text` | Build/store immutable unsigned digest quote |
| `bsv_publish_sign` | `workflow_id` | Separately approved, locked-budget signing; no raw signed bytes returned |
| `bsv_publish_submit` | `workflow_id` | Separately approved single attempt; never automatic retry |
| `bsv_publish_status` | `workflow_id` | Local workflow and ledger receipt, no provider call |
| `bsv_publish_receipt` | `workflow_id` | Exact readback reconciliation only |
| `bsv_spend_policy_status` | `{}` | Shared total/session committed and remaining amounts |

## Recovery and evidence limits

`begin_signing` durably holds aggregate budget and outpoints **before custody**.
Lost signer results, failed signatures after the claim, and crashes remain held;
replay never invokes signing again. Signed bytes and approval consumption markers
remain private. Dispatch is durably claimed before network I/O. Accepted HTTP
response alone is not success: only matching provider txid **and raw transaction
hash readback** can mark the workflow `submitted` and settle budget accounting.
`uncertain` retains all locks. Repeated submit never resends; use receipt. A later
provider outage cannot undo settled accounting or erase an earlier receipt.

A crash between separate ledger/journal writes can conservatively strand a
`signing`/`prepared` reservation. There is no automated repair or free budget.
Preserve both stores and obtain trusted manual reconciliation. Do not regenerate
keys or delete approval markers. This is at-most-once dispatch, not guaranteed
delivery or a multi-database atomic transaction.

`submitted`/`settled` is provider-observed transport/accounting evidence, not
trusted-header inclusion, consensus validity, mining, finality, complete logging,
human identity, authorship or truth. Native signature checks cover only the
supported compressed-P2PKH ALL|FORKID subset. The tests use invented ancestry and
fresh never-funded keys. **No funded mainnet canary or public broadcast has been
performed for this candidate.**
