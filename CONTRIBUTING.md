# Contributing to Argus

Thank you for contributing to Argus.

## Rules
1. All changes must be tested: `cargo test` for Rust and `pytest tests` for Python.
2. Code must pass `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`.
3. Do not add external network dependencies or telemetry.
4. Cryptographic invariants (fail-closed verification, anchor enforcement) must be preserved.
5. Contributions are licensed under the MIT License.
