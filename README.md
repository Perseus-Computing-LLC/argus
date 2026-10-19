# Argus

> Tamper-evident, append-only audit ledger for AI agents: a linear SHA-256 hash chain with optional signatures.

[![Crates.io](https://img.shields.io/crates/v/argus-ledger.svg)](https://crates.io/crates/argus-ledger)
[![PyPI](https://img.shields.io/pypi/v/argus-ledger.svg)](https://pypi.org/project/argus-ledger/)
[![docs.rs](https://docs.rs/argus-ledger/badge.svg)](https://docs.rs/argus-ledger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** by [Perseus Computing LLC](https://perseuscomputing.com).

## What it does

When agents run commands, call APIs or edit files, Argus keeps an ordered record that shows whether anything was changed afterwards:

- **Linear SHA-256 hash chain.** Each event's hash covers its sequence number, event ID, timestamp, event type, actor, the previous event's hash and a digest of its canonical JSON payload (`compute_event_hash` in `src/argus_ledger/hasher.py`; `src/lib.rs`).
- **Tamper detection.** `verify_chain` walks the chain from genesis and reports the first sequence whose hash or link does not check out (`first_broken_sequence`, `src/argus_ledger/ledger.py`).
- **Anchors and signatures.** Verifying against an anchor, a sequence number and hash kept outside the ledger, catches a ledger that was rewritten and re-hashed from genesis. With a signing key, each event also carries an HMAC-SHA256 or Ed25519 signature that verification checks (`src/argus_ledger/hasher.py`, `src/argus_ledger/ledger.py`; Rust: `VerificationPolicy` in `src/lib.rs`).
- **No network code.** The ledger runs locally and sends nothing anywhere.

## Installation

crates.io and PyPI have 0.1.0-alpha.2 (0.1.0a2 on PyPI). This README describes 0.1.0-alpha.4, which is not published yet. Until it is, install from this repository.

### Rust

```toml
[dependencies]
argus-ledger = { git = "https://github.com/Perseus-Computing-LLC/argus", branch = "main" }
```

### Python

```bash
pip install "argus-ledger @ git+https://github.com/Perseus-Computing-LLC/argus@main"
```

## Quickstart

### Rust

```rust
use argus_ledger::{AuditLedgerWriter, AuditVerifier, InMemoryLedger, VerificationPolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = InMemoryLedger::new();
    let ev1 = ledger.append("tool.call", "agent_1", r#"{"command":"cargo test","tool":"bash"}"#)?;
    let ev2 = ledger.append("file.patch", "agent_1", r#"{"file":"Cargo.toml","status":"modified"}"#)?;
    let policy = VerificationPolicy { anchor: Some(ev2.anchor()), ..Default::default() };
    let report = ledger.verify_chain_with(&policy)?.ensure_valid()?;
    println!("Ledger verified intact: {} events chained to head {}", report.total_events, &ev2.event_hash[0..16]);
    Ok(())
}
```

### Python

```python
from argus_ledger import AppendOnlyLedger

ledger = AppendOnlyLedger("audit.jsonl")
ev1 = ledger.append("tool.call", "agent_1", {"command": "cargo test", "tool": "bash"})
ev2 = ledger.append("file.patch", "agent_1", {"file": "Cargo.toml", "status": "modified"})
report = ledger.verify_chain(anchor=ev2.anchor())
assert report.valid is True
print(f"Audit log verified: {report.total_events} events chained up to sequence {ev2.sequence}")
```

## Measurements

Benchmark reports, with hardware and method, are kept in [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) rather than repeated here.

## Limits

- **Alpha release:** APIs and formats are subject to revision before 1.0.
- **Linear chain:** Verification reads every event, so it takes time proportional to the ledger's length, and there are no inclusion proofs for single events.
- **Anchoring requirement:** An unanchored chain that is rewritten and re-hashed from genesis is internally consistent. Keep head hashes outside the ledger, or in signed checkpoints, to detect a complete rewrite.
- **Storage scope:** The Rust crate provides `InMemoryLedger`. The Python package writes a local JSONL file locked with `fcntl`, so it runs on Linux and macOS, not Windows.
- **Not independently assessed:** Designed for local and disconnected use.

## Links

- [Documentation (docs.rs)](https://docs.rs/argus-ledger)
- [Security Policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md)
- [Telarch Overview](https://telarch.ai)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
