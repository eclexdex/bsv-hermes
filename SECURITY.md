# Security boundaries

The native product is offline/custody-free: no transport, key, wallet, spend, signing, broadcast, arbitrary URL/file read, execution hook or automatic profile mutation. Importing runtime modules performs no host discovery or network access. Native registration uses the host's plugin-relative configuration API only for explicit group selection and registers three packaged read-only skills.

Hermes plugins are trusted local Python, not a sandbox. The native tools accept supplied bytes/digests/projections, not paths. Retained identity library filesystem helpers are **unregistered**, POSIX-oriented historical APIs, not part of the portable native security boundary; do not use them as a general secret-file reader. No private-opening CLI is bundled.

Unknown fields, wrong types, non-JSON values, cycles and resource excess reject at a shared pre-serialization guard, with stricter per-protocol schemas. Error messages never echo raw content. Native result envelopes are unified; comparison failure is not execution failure. Invalid approvals and advisory deployment results do not grant any authority.

Do not send seeds, keys, credentials, actual private SOUL/persona content or private host config. Host logs/history can retain input arguments, including supplied nonces. Deterministic commitments allow guessing. Batch proofs remain deterministic and may reveal low-entropy leaves by dictionary guesses despite salting the final root; native proof output is opt-in private export. Keep proofs and opening/projections local; publication requires separate consent.

The local installer is explicit-profile, dry-run by default, refuse-overwrite and hash-verified. It checks selected source/target ancestry for symlinks, rejects hardlinked source files, uses exclusive new destinations and verifies readback. It requires a trusted local filesystem and no concurrent same-UID/root mutation of target ancestors; these portable checks are not a hostile-filesystem sandbox or full race-proof Windows containment. Native runtime never calls the installer. Manifest hashes detect drift/corruption, not malicious-author authenticity.

The host smoke blocks socket connects and uses only temporary synthetic homes/config, but is not an OS sandbox. Production privacy/logging settings, authentic human approval, signing keys, chain proofs, consensus/SPV, SDK conformance and legal/license clearance were not validated. Report vulnerabilities privately to the operator until an approved maintainer/security channel exists.
