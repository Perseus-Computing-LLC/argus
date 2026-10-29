# argus-ledger-native

Python extension module built from the `argus-ledger` Rust crate with pyo3. It exposes the
streaming chain verifier (`ChainVerifier` / `VerificationPolicy::verify_stream`) and
`AuditEvent::to_json_line` so that `argus_ledger.AppendOnlyLedger.verify_chain` runs one
implementation of the hash, the timestamp rule and the fail-closed parse in both languages.

The pure-Python package does not require it. When `argus_ledger_native` is importable,
`verify_chain` uses it for unsigned and Ed25519-signed ledgers and reports `verifier="native"`;
HMAC-signed ledgers, and any process with `ARGUS_LEDGER_PURE_PYTHON=1` set, use the Python loop
and report `verifier="python"`. The cross-verifier matrix test holds the two paths to identical
verdicts.

Build into the current environment: `pip install maturin && maturin develop --release` from
this directory (`bindings/python`). Build a wheel: `maturin build --release`.
