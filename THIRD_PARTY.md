# Source and dependency policy

The six default tools and three offline kits use only the Python standard library.
Hermes is a separately installed host; setuptools is build tooling. The optional
`mainnet` extra requires **bsv-sdk==2.4.0** and **cryptography==48.0.0**. Install it
in a dedicated interpreter: do not replace the Hermes host's crypto dependencies.

## Reviewed selection

- Official [BSV Python SDK](https://github.com/bsv-blockchain/py-sdk), source commit
  `c16fd32814a0a2c23588f140446069acdb7b5b5e`, release 2.4.0. Exercised CPython 3.12
  macOS arm64 wheel SHA256:
  `dcbaa1c2b478bacf2bb6a3fe50c8b005870c24750019cbcc5246a9d4123aa9a1`.
- [PyCA cryptography](https://github.com/pyca/cryptography) 48.0.0, universal2 wheel
  SHA256 `0c558d2cdffd8f4bbb30fc7134c74d2ca9a476f830bb053074498fbc86f41ed6`.
- The [complete exercised binary-wheel lock](bsv_hermes/mainnet/resources/requirements-macos-py312.txt)
  pins all 20 distributions with hashes. It is platform-specific; another platform
  needs its own reviewed wheels and rerun, not an undocumented fallback.
- The signer enforces both direct versions and native libsecp256k1. It compares
  SDK signing preimages to independent serialization and checks each completed
  compressed-P2PKH ALL|FORKID signature using PyCA/OpenSSL. This is not a complete
  SDK audit, native reproducible-build proof or general Script consensus verifier.

## Licensing and notices

**The BSV SDK is Open BSV License version 4, not MIT.** Its terms restrict use to
the BSV blockchains defined there. Embedded libsecp256k1 is MIT; cryptography is
Apache-2.0 OR BSD-3-Clause. All retained upstream dependency texts, including
transitive notices, are in [NOTICES.md](bsv_hermes/mainnet/resources/NOTICES.md).
Those exact texts govern; no SDK source, wheel or native binary is vendored.

The first-party prototype components were integrated under `bsv_hermes.mainnet`.
Candidate prototype MIT declarations were not adopted. Product attribution,
copyright and release license remain pending operator decision. Dependency
notices neither select nor imply a license for this repository.

No research mirrors, raw evidence, machine-local helpers, wallet files, private
authority material, grants or live profile configuration belong in the shipping
inventory. See [license policy](LICENSE-POLICY.md), [provenance](PROVENANCE.md) and
[mainnet boundaries](docs/MAINNET.md).
