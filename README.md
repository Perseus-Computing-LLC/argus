# argus-ledger

> Append-only SHA-256 audit log for autonomous agents.

[![Crates.io](https://img.shields.io/crates/v/argus-ledger.svg)](https://crates.io/crates/argus-ledger)
[![docs.rs](https://docs.rs/argus-ledger/badge.svg)](https://docs.rs/argus-ledger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Perseus** suite by [Perseus Computing LLC](https://github.com/Perseus-Computing-LLC).

---

## Why Argus exists

When autonomous agents run shell commands, call APIs, or mutate files, you need a reliable record of what happened and proof that logs were not changed after the fact.

Argus records every event into an append-only sequence where each entry includes the SHA-256 hash of the previous record. If any entry is altered or deleted, verification fails immediately and points directly to the modified index.

---

## Key design goals

- **Continuous hash chaining:** Every event links cryptographically to the one before it, rooted at genesis.
- **Fast tamper detection:** Scans 100,000 events in 46.00 &micro;s and fails closed the moment a single byte does not match.
- **Low latency appends:** Appending an event takes 4.12 &micro;s, fast enough to log every action inline during agent execution.
- **Self-contained:** Runs fully offline as an in-memory library without external audit services or cloud dependencies.

---

## Installation

Add `argus-ledger` to your `Cargo.toml`:

```toml
[dependencies]
argus-ledger = "0.1.0-alpha.2"
```

Or via Cargo:

```bash
cargo add argus-ledger
```

---

## Example

```rust
use argus_ledger::{
    AuditLedgerReader, AuditLedgerWriter, AuditVerifier, InMemoryLedger,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger = InMemoryLedger::new();

    // 1. Record agent startup
    let ev1 = ledger.append(
        "AGENT_BOOTSTRAP",
        "runtime:node_0",
        r#"{"model":"qwen2.5-coder-32b","temperature":0.2}"#,
    )?;
    println!("Sequence #{}: Hash {}", ev1.sequence, &ev1.event_hash[0..16]);

    // 2. Record tool execution
    let ev2 = ledger.append(
        "TOOL_INVOCATION",
        "runtime:node_0",
        r#"{"tool":"terminal","command":"cargo test --workspace"}"#,
    )?;
    println!("Sequence #{}: Hash {}", ev2.sequence, &ev2.event_hash[0..16]);

    // 3. Verify cryptographic integrity
    let report = ledger.verify_chain()?;
    assert!(report.valid, "Chain integrity compromised");
    println!(
        "Chain verified intact: {} blocks validated across sequence.",
        report.total_events
    );

    Ok(())
}
```

---

## Benchmark results

Measured on bare-metal Linux x86_64 (`rustc 1.85.0`, `opt-level = 3`, `lto = "fat"`):

| Metric | Measurement | Test condition |
| :--- | :--- | :--- |
| **Append Latency** | **4.12 &micro;s** | Sequential event hashing and append |
| **Tamper Detection Latency** | **46.00 &micro;s** | Scan across 100k events |
| **Verification Throughput** | **2,170,000 events/s** | Full chain validation traversal |
| **Tamper Detection Rate** | **100.00%** | Single-bit byte flip sensitivity |
| **External Dependencies** | **0** | Standalone offline primitives |

Run benchmarks yourself:

```bash
cargo run --release -p perseus-benchmarks
```

---

## License

Copyright &copy; 2026 Perseus Computing LLC. Released under the [MIT License](LICENSE).
