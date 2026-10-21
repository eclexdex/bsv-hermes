# Contributing

This is an unpublished prototype pending owner, visibility and license decisions. Do not publish or submit third-party code until rights and provenance are reviewed. Do not add wallet state, keys, seed phrases, environment files or research snapshots.

Use vertical strict TDD: write a behavioral test, observe the expected failure, implement minimally, run the targeted and full suites. Record red/green observations in local ignored verification receipts, not runtime artifacts. Tests must not call chain services or mutate Hermes profiles. Avoid dependency changes unless separately reviewed. Runtime is stdlib-only.

Run `python -m unittest discover -s tests -v`. When Hermes is available run `python scripts/native_smoke.py .` using its dependency environment. A skipped host integration test is not evidence of native compatibility. Build wheel/source artifacts with trusted standard Python build tooling and install/test the wheel from another directory. Validate source distribution with Plugin Doctor independently of library-wheel checks.

After reviewed source changes regenerate the canonical inventory with `python scripts/update_manifest.py`, then check it and exercise the explicit installer in a temporary profile. Do not modify the inventory to hide unexplained drift. Changes to public tool arguments, output types, parser limits, commitment format, execution authority or network behavior need explicit contract review. BEEF and read-only chain access are future work, not placeholders to silently advertise. Signing/payment/broadcast remain excluded. Parent review owns acceptance and commits.
