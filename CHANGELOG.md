# Changelog

All notable changes to `argus` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Repair set from the 2026-10-28 review. Finding ids refer to that review. No version bump.

### Added
- **#14:** accept-as-historic timestamp cutoff for ledgers written before the strictly-increasing
  timestamp rule (F5). `argus-verify --legacy-timestamps-before <seq>`, Python
  `verify_chain(legacy_timestamps_before=seq)` and Rust
  `VerificationPolicy::legacy_timestamps_before: Option<u64>` apply one rule: below `seq`, a
  timestamp that is not strictly after its predecessor's is counted in the report's
  `legacy_timestamp_regressions` and reported once (report `warnings`; CLI `warnings` JSON array
  and one stderr line; Python `UserWarning`) instead of failing the chain. Hashes, `prev_hash`
  links, sequence continuity, malformed timestamps and malformed lines stay strict, and the
  strict rule applies from `seq` onwards. `seq` must be at least 1; unset, behaviour is unchanged.
  The cross-language matrix test covers a regression at sequence 5 of 10 under no cutoff, cutoff
  6 and cutoff 5, and hash tampering below the cutoff, across every writer and verifier.
  `argus-verify --json` output now always carries `warnings` (and `legacy_timestamp_regressions`
  on success).

### Fixed
- **F1 (critical):** Rust `AuditEvent::to_json_line` built the record line with `format!`, so an
  actor containing `"` or `\` (both ASCII-graphic, so accepted by `validate_identifiers`) produced
  a line no reader could parse, after which every append and every verifier failed on an honest
  ledger. Every string field is now serialized through serde_json; the payload is spliced in
  verbatim as a `RawValue` (it is already canonical JSON and the hash commits to those bytes).
  Field order and `"signature":null` are unchanged, so existing records and the Python writer stay
  byte-identical. `validate_identifiers` now also rejects `"` and `\` in `actor`.
- **F2 (high):** `argus-verify` skipped any line it could not parse and reported a torn or
  vandalised tail as a valid chain. Every non-blank line must now parse as a complete record, or
  the verdict is FAILED at that file position (exit 1). The position is counted, never read from
  the record.
- **F3 (high):** `verify_chain` (Python) and `FileLedger::verify_chain` (Rust) read the whole
  file into memory before checking the first record. Both now verify in one streaming pass with
  one record resident; `VerificationPolicy::verify_stream` and `ChainVerifier` are the Rust
  entry points and `argus-verify` uses them too.
- **F5 (high):** one timestamp contract across all writers and verifiers: timestamps are
  strictly increasing when compared as instants. Rust parses RFC 3339 with any UTC offset
  (`+05:00`, `Z`, none) via `split_utc_offset`; `parse_timestamp_nanos` is public. The Python
  writer takes `max(now, last + 1 µs)` under the append lock (production showed clock-step
  regressions) and keeps its RFC 3339 `+00:00` format. Python `verify_chain` applies the same
  strictly-increasing check as the Rust library and CLI. A cross-language matrix test runs
  {Python, Rust} writer × {Python verify, Rust library, `argus-verify`} over equal timestamps,
  offsets, torn tails, empty actors and 2^53-1 integers; every cell must agree.
- **F17:** `AuditEvent` carries `hash_version` (absent parses as 1, as in Python); the Rust
  verifier recomputes each record's hash in its own format, so legacy format-1 records verify
  and a relabelled record cannot. `ChainVerificationReport.legacy_events` counts them.
- **F8:** `argus-verify --json` output is built with serde_json; record content can no longer
  inject keys into it.
- **F16:** `FileLedger::all_events` no longer "unlocks" a different file descriptor.
- **F4:** the 0.1.0-alpha.7 entry below no longer claims exponent-form floats verify in Rust.

### Changed
- **F6/F7:** the Python writer applies the Rust identifier grammar (`validate_identifiers`:
  same regex, 256-byte cap, raises `IdentifierError`) and refuses payload integers outside
  ±(2^53-1) (`IntegerRangeError`), non-object payloads and canonical encodings over 1 MiB
  (`PayloadError`). `reject_float_payload` is renamed `validate_payload`; the old name is kept as
  an alias. `FloatPayloadError` now subclasses `PayloadError`.
- **F15:** CI builds the Rust crate (debug and release) in the Python job before pytest; with
  `CI=true` the cross-language tests fail instead of skipping when the artifacts are missing.
- **F14:** README throughput figures are labelled in-memory / verify-phase-only.
- **F11:** `argus_ledger.proofweave` is marked experimental (`RAGTriadBinding` emits floats the
  ledger refuses).
- `argus-verify --benchmark` measures open+parse+verify per iteration and says so.
- Rust sources are `cargo fmt` formatted and clippy-clean, so the Rust CI job can pass.

## [0.1.0-alpha.7] - 2026-10-27

### Security / correctness note — float payloads and the Rust verifier (found 2026-10-27)
On a production ledger of 32,908 events, `argus-verify 0.1.0-alpha.6` reported
`Event hash mismatch at seq 30936` while the Python `verify_chain()` passed. The record's payload held
`"top_score": -9.865914147294541`, written by the Python library (shortest round-trip repr, 16 digits).
serde_json's default float parser is not correctly rounded; it read the value as `-9.86591414729454`,
re-serialized it that way, and the payload digest changed. 41 of the 32,908 events carried floats
(22 `tool_execution` from the Kibisis plugin's `top_score`, 19 `tci.self_improvement_cycle`). The chain
itself was intact: this was a verifier defect, not tampering, but it meant the released Rust verifier
could not independently confirm a ledger the Python library had written.

### Fixed
- `argus-verify` builds `serde_json` with `float_roundtrip`, so float payloads whose shortest
  round-trip repr has 16-17 significant digits (such as `-9.865914147294541` above) parse exactly
  and verify again. Kept permanently: the ledger is append-only.
- **Not fixed by this (corrected 2026-10-28):** `float_roundtrip` changes parsing, not formatting.
  A float that Python printed in exponent notation (`1e-05`, `1e-07`, anything with |x| < 1e-4)
  is re-serialized by serde_json as `1e-5`/`1e-7`, the payload digest differs, and the Rust side
  (`argus-verify` and `FileLedger::verify_chain`) still reports `Event hash mismatch` for that
  record while the Python `verify_chain()` passes. Pre-alpha.7 ledgers holding such values cannot
  be verified by the Rust side; use the Python verifier for them. Values such as `0.5`,
  `0.30000000000000004`, `1e+16` and `-0.0` are unaffected.

### Changed
- **The Python writer now refuses floats** (`FloatPayloadError` from `AppendOnlyLedger.append`), matching the
  Rust writer's `validate_canonical_payload`. Nothing is written when the check fails. Callers pass integers
  (basis points, micro-units, milliseconds) or fixed-format strings (`f"{x:.6f}"`); the two writers then
  produce byte-identical canonical JSON and neither side depends on IEEE-754 formatting (`1e-07` vs `1e-7`,
  16- vs 17-digit shortest repr). `reject_float_payload()` is exported for callers that want to check early.
- CI: every action is pinned to a full commit SHA (the Rust toolchain action followed a branch) and
  runs on Node 24. Dependabot proposes weekly grouped updates for actions, Cargo and Python
  dependencies once a release is 7 days old, and an OpenSSF Scorecard workflow reports to code
  scanning.
- Dependencies: ed25519-dalek 3, sha2 0.11 and getrandom 0.4 (`getrandom::fill` replaces
  `getrandom::getrandom`). The MSRV rises from 1.85 to 1.88, which sha2 0.11 requires.

## [0.1.0-alpha.6] - 2026-10-25

### Added
- Rust: native `FileLedger` supporting persistent append-only storage in JSON-L format with Unix `0600` permissions, POSIX advisory file locking, and `sync_data()` durability.
- Rust: implemented `AuditLedgerWriter`, `AuditLedgerReader`, and `AuditVerifier` traits on `FileLedger`.
- Interoperability: verified byte-for-byte SHA-256 canonical JSON hash parity and cross-language verification between Python `AppendOnlyLedger` and Rust `FileLedger`.

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
