# Argus

> Tamper-evident append-only SHA-256 provenance and audit ledger for autonomous agents.

[![Crates.io](https://img.shields.io/crates/v/argus-ledger.svg)](https://crates.io/crates/argus-ledger)
[![PyPI](https://img.shields.io/pypi/v/argus-ledger.svg)](https://pypi.org/project/argus-ledger/)
[![docs.rs](https://docs.rs/argus-ledger/badge.svg)](https://docs.rs/argus-ledger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** by [Perseus Computing LLC](https://perseuscomputing.com).

## What it does

When autonomous agents run shell commands, invoke APIs, or modify files, systems require an indisputable record of actions. Argus provides:
- **Linear SHA-256 hash chain:** Every event binds sequence number, event ID, timestamp, event type, actor ID, the previous event hash, and canonical payload digest.
- **Fail-closed tamper detection:** Verifies cryptographic continuity from genesis to head; any modification to an event's data or ordering breaks the chain and locates the first affected sequence.
- **Anchored heads and Ed25519 signing:** Anchoring the head hash in a signed checkpoint note (or external store) ensures that even a full-chain rewrite is caught and rejected.
- **Zero network code:** Runs locally on your hardware without external cloud services or telemetry.

## Installation

### Rust

Add `argus-ledger` to `Cargo.toml`:

```toml
[dependencies]
argus-ledger = "0.1.0-alpha.3"
```

### Python

Install via pip:

```bash
pip install argus-ledger
```

## Quickstart

### Rust (10 lines)

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

### Python (10 lines)

```python
from argus_ledger import AppendOnlyLedger

ledger = AppendOnlyLedger("audit.jsonl")
ev1 = ledger.append("tool.call", "agent_1", {"command": "cargo test", "tool": "bash"})
ev2 = ledger.append("file.patch", "agent_1", {"file": "Cargo.toml", "status": "modified"})
report = ledger.verify_chain(anchor=ev2.anchor())
assert report.valid is True
print(f"Audit log verified: {report.total_events} events chained up to sequence {ev2.sequence}")
```

## What we measured

Figures trace to reports committed in [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) (Linux x86_64, Intel Core i5-13500, `rustc 1.97.1`):

| Metric | Result | Range | Scope | Method |
|---|---|---|---|---|
| **Append Throughput (1M Events)** | **809,697 events/s** | 809k–893k events/s | 1,000,000 sequential appends with SHA-256 chaining | `argus_1m_scale` |
| **Average Append Latency** | **1.24 µs/event** | 1.12–1.24 µs | 1,000,000 events, in-memory | `argus_1m_scale` |
| **Linear Verification Throughput** | **2,433,053 events/s** | 2.43M–2.64M events/s | Full chain verification from genesis to head | `argus_1m_scale` |
| **Tamper Detection Latency** | **185.35 ms** | 177k–185k µs | Edit at sequence #500,000 in 1M event ledger | `argus_1m_scale` |
| **Tamper Detection Position** | **Sequence #500,000** | #500,000 | Linear walk stops fail-closed at first break | `argus_1m_scale` |
| **Anchored Rewrite Caught** | **100% caught** | - | Full-chain rewrite rejected against anchor | `argus_anchored_checkpoints` |
| **Checkpoint Signing Latency** | **35.52 µs** | 30–50 µs | Ed25519 digital signature in C2SP note format | `argus_anchored_checkpoints` |

## Limits

- **Alpha release:** APIs and formats are subject to revision before 1.0.
- **Linear chain, not a Merkle tree:** Argus uses a strictly linear SHA-256 hash chain where verification complexity is O(n). It does not provide O(log n) tree inclusion proofs.
- **Anchoring requirement:** An unanchored chain that is completely rewritten and re-hashed is internally consistent. Head hashes must be anchored in signed checkpoints or committed to external storage to detect complete history rewrites.
- **Storage scope:** The Rust crate provides `InMemoryLedger`. The Python package persists to a local JSONL file with POSIX file locking (`fcntl`).
- **Not independently assessed:** Designed for local and disconnected use.

## Links

- [Documentation (docs.rs)](https://docs.rs/argus-ledger)
- [Evidence & Claims](https://telarch.ai/evidence)
- [Security Policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md)
- [Telarch Overview](https://telarch.ai)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
