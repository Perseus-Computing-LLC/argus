# Changelog

All notable changes to `argus` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
