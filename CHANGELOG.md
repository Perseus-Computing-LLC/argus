# Changelog

All notable changes to `argus` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.5] - 2026-10-22

### Security
- Python: a ledger verified with only an Ed25519 public key accepted events forged by anyone who
  knew that public key. `verify_signature` let the signature choose its scheme, so it accepted an
  HMAC-SHA256 "signature" keyed with the public key, and for `ed25519:` signatures it also retried
  the key as a private seed, so an Ed25519 signature made with the public key's bytes as the seed
  verified too. Both forgeries rewrote a whole chain that `verify_chain` then reported as valid.
  The verifier now chooses the scheme. The Rust crate was not affected: its `VerificationPolicy`
  takes a typed Ed25519 public key.

### Changed
- Python: `AppendOnlyLedger(path, verify_key=public_key)` checks an Ed25519-signed ledger with its
  32-byte public key. It accepts Ed25519 signatures only and cannot append (`PermissionError`).
- Python: passing an Ed25519 public key as `signing_key`, the way 0.1.0-alpha.4 documented checking
  an Ed25519 ledger, no longer verifies one. `signing_key` is an HMAC secret: the ledger now
  rejects `ed25519:` signatures, with an error that names `verify_key`. Switch to `verify_key=`.
- Python: `verify_signature(event, key, *, scheme="hmac")` takes the scheme from the caller,
  `"hmac"` (the default) or `"ed25519"` with a public key, and no longer derives a public key from
  the key it is given.

## [0.1.0-alpha.4] - 2026-10-19

### Fixed
- `cryptography` is a declared dependency. Ed25519 signing and verification import it, but
  `pip install argus-ledger` did not install it, so Ed25519 failed with `ModuleNotFoundError`.
- Version strings agree: `pyproject.toml` said 0.1.0a3 while `argus_ledger.__version__` said 0.1.0a4.
- README claims checked against the code. Removed: the measured-figures table (kept in
  telarch-benchmarks) and the signed checkpoint note, which this repository does not implement;
  anchors are a sequence number and hash passed to `verify_chain`. The README now says the Python
  package needs `fcntl`, so it does not run on Windows.
- SECURITY.md and the README no longer call the log immutable or describe signed checkpoints.

### Added
- Release workflow: builds and attests the sdist, wheel and crate, installs the wheel with its
  dependencies on Ubuntu and macOS arm64, creates a GitHub release naming the commit, and publishes
  to PyPI and crates.io by trusted publishing from protected environments.
- CI runs the Python tests on macOS arm64 as well as Ubuntu, and installs the built wheel in a clean
  virtual environment.

## [0.1.0-alpha.3] - 2026-10-18

### Added
- Hash format 2: SHA-256 over length-prefixed binary field serialization (`argus.event.v2\0`) preventing adjacent field ambiguity.
- Head anchoring via `ChainAnchor` and `VerificationPolicy` to detect rollback, truncation, and full-chain rewrites.
- Ed25519 signatures on individual events. Correction: this entry also listed C2SP signed
  checkpoint notes, which this repository does not implement.
- Adopted RustCrypto `sha2` and `ed25519-dalek` crates.
- MSRV enforcement for `rust-version = "1.85"` in `Cargo.toml`.

### Changed
- Removed deprecated "merkle-tree" descriptions; Argus is accurately documented as a linear SHA-256 hash chain.
- Standardized clippy warnings with zero warnings under `-D warnings`.

## [0.1.0-alpha.2] - 2026-10-13

### Added
- Initial public release of `argus-ledger` crate and Python package.
- Linear hash chaining and fail-closed positional tamper detection.
