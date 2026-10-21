FUNDED CANARY — PROCEDURE ONLY, NOT AUTHORIZATION

Status: FUNDED CANARY NOT EXECUTED. Only synthetic never-funded keys and loopback fixtures are used in software tests. No real funding, operator-key signing or public POST is authorized by this procedure. The operator owns every approval-bearing action. Empty fields are blockers, not defaults.

Before any canary, operator must approve a written manifest containing:
  network and expected chain/checkpoint:
  dedicated disposable wallet identifier and public-address fingerprint:
  custody method / operator key reference (never paste seed/private key):
  independently verified funding source and approved funding amount in satoshis:
  exact authorized outpoints and source transaction hashes:
  funding confirmation policy and selected-chain validation method:
  permitted transaction output amount(s) in satoshis:
  commitment OP_FALSE OP_RETURN output amount (normally zero, requires explicit approval):
  change address and independently checked wallet ownership:
  absolute fee cap in satoshis and fee rate cap satoshis/byte:
  maximum total debit/loss and minimum change/dust policy:
  exact synthetic payload bytes, domain/version, digest or batch root:
  approved provider endpoint, TLS identity and no-retry submission policy:
  named approving operator, approval expiry and one-use authorization identifier:

Use the smallest operator-approved funding amount meeting current relay/dust/fee constraints. Do not prescribe an unverified universal amount or fee. No sensitive prompts, private artifacts, addresses beyond intended public wallet metadata, signatures-as-consent claims, or credentials in payload. Hash commitments are public and dictionary-guessable: use an explicitly approved nonce commitment design where confidentiality requires it.

1. Finish license/ownership, dependency and isolated-custody reviews. Re-run release gates on exact staged receipt/verifier source. Preserve source/archive hashes and five independent verification dimensions.
2. In a dedicated operator-controlled environment, create/select a never-reused canary wallet using supported custody workflow. Independently verify public receiving/change addresses. Human explicitly approves wallet creation and funding before either action. Worker/model must not receive the key.
3. Human funds only the approved amount; bounded GET observes exact outpoints. Treat provider reports separately from chain-validated confirmations. Do not infer finality from an API response. Stop on unrecognized funds or address mismatch.
4. Build quote/unsigned transaction locally using existing mainnet approval workflow. Present exact payload bytes, all inputs/outputs, change address/amount, fee, fee rate, total debit and expiry. Human separately approves these exact bytes/outpoints. Any quote/input/payload/fee/endpoint change invalidates approval.
5. Only authorized operator signer signs after explicit one-use signing approval. Independently inspect signed transaction bytes and verify signatures/commitment/output amounts/fee bounds. Do not broadcast at signing time.
6. Require separate exact-transaction broadcast approval tied to raw transaction hash, destination endpoint and expiry. Operator explicitly permits one public POST. On timeout, ambiguous response or HTTP 429: checkpoint and stop; do not rebuild/re-sign/retry blindly. Resolve by bounded readback first, under a new operator instruction if necessary.
7. Preserve actual signed transaction, actual provider receipt and exact readback. Never invent a txid/receipt. Independently bind commitment to raw transaction and txid, Merkle path to header, and header to explicitly selected validated chain. If chain validation is unavailable, label it unchecked even if a provider reports mined.
8. Run standalone installed verifier with explicitly approved artifact paths and caller-trusted public key. Report artifact, evidence chain, signature, batch, inclusion independently. Missing signed events remain unverified source; no overall green badge or proof of execution claim.
9. Record actual debit/fee/remaining balance and approval audit. No automatic sweep or second spend: change disposition needs a separate operator approval. Retain only approved public evidence. Close canary with limitations, not a production security certification.
