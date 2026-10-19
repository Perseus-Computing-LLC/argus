# Changelog

All notable changes to `argus` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.4] - Unreleased

### Fixed
- `cryptography` is a declared dependency. Ed25519 signing and verification import it, but
  `pip install argus-ledger` did not install it, so Ed25519 failed with `ModuleNotFoundError`.
- Version strings agree: `pyproject.toml` said 0.1.0a3 while `argus_ledger.__version__` said 0.1.0a4.
- README claims checked against the code. Removed: the measured-figures table (kept in
  telarch-benchmarks) and the signed checkpoint note, which this repository does not implement;
  anchors are a sequence number and hash passed to `verify_chain`. The README now says the Python
  package needs `fcntl`, so it does not run on Windows.

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
- Ed25519 digital signatures on individual events and C2SP signed checkpoint notes.
- Adopted RustCrypto `sha2` and `ed25519-dalek` crates.
- MSRV enforcement for `rust-version = "1.85"` in `Cargo.toml`.

### Changed
- Removed deprecated "merkle-tree" descriptions; Argus is accurately documented as a linear SHA-256 hash chain.
- Standardized clippy warnings with zero warnings under `-D warnings`.

## [0.1.0-alpha.2] - 2026-10-13

### Added
- Initial public release of `argus-ledger` crate and Python package.
- Linear hash chaining and fail-closed positional tamper detection.
