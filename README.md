# argus-ledger

> Append-only SHA-256 audit log for autonomous agents.

[![Crates.io](https://img.shields.io/crates/v/argus-ledger.svg)](https://crates.io/crates/argus-ledger)
[![docs.rs](https://docs.rs/argus-ledger/badge.svg)](https://docs.rs/argus-ledger)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** (TCI / Telarch Cognitive Infrastructure) by [Perseus Computing LLC](https://github.com/Perseus-Computing-LLC).

---

## Why Argus exists

When autonomous agents run shell commands, call APIs, or mutate files, you need a reliable record of what happened and proof that logs were not changed after the fact.

Argus records every event into an append-only sequence where each entry includes the SHA-256 hash of the previous record. If any recorded entry is altered, reordered, or removed from the middle of the chain, verification fails and reports the first affected position. Removing the newest entries, or recomputing the whole chain, is detected against an anchor kept outside the writer's reach, or by signature checks when the writer's key is out of the attacker's reach.

---

## Key design goals

- **Continuous hash chaining:** Every event links cryptographically to the one before it, rooted at genesis.
- **Fail-closed tamper detection:** Verifies cryptographic continuity and aborts immediately when any hash or payload is corrupted. Tampered event #42 is detected in ~46.5 &micro;s.
- **Low latency appends:** In-memory sequential appends with SHA-256 chaining execute at ~600,000 events/s (~1.67 &micro;s/event).
- **High throughput chain verification:** Traverses and validates complete cryptographic sequences at ~839,000 events/s (~1.19 &micro;s/event).
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
    AuditLedgerWriter, AuditVerifier, InMemoryLedger, VerificationPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = InMemoryLedger::new();

    // 1. Record agent startup. Payloads are canonical JSON objects: sorted keys, no
    //    whitespace, integers only (`validate_canonical_payload`).
    let ev1 = ledger.append(
        "agent.bootstrap",
        "runtime:node_0",
        r#"{"model":"qwen2.5-coder-32b","seed":7}"#,
    )?;
    println!("Sequence #{}: Hash {}", ev1.sequence, &ev1.event_hash[0..16]);

    // 2. Record tool execution
    let ev2 = ledger.append(
        "tool.invocation",
        "runtime:node_0",
        r#"{"command":"cargo test --workspace","tool":"terminal"}"#,
    )?;
    println!("Sequence #{}: Hash {}", ev2.sequence, &ev2.event_hash[0..16]);

    // 3. Publish the head to a place the writer cannot rewrite, then verify against it.
    //    `ensure_valid` turns a failed report into an error, so `?` fails closed.
    let policy = VerificationPolicy {
        anchor: Some(ev2.anchor()),
        ..VerificationPolicy::default()
    };
    let report = ledger.verify_chain_with(&policy)?.ensure_valid()?;
    println!(
        "Chain verified intact: {} blocks validated across sequence.",
        report.total_events
    );

    Ok(())
}
```

`verify_chain()` without an anchor checks internal consistency only: an empty, truncated, or fully recomputed chain passes it. `InMemoryLedger::with_signing_key` signs every event with Ed25519, and `VerificationPolicy::verifying_key` makes a valid signature mandatory on every event.

### Hash format

Event hashes use format 2, shared byte for byte by the Rust crate and the Python package: SHA-256 over the tag `argus.event.v2\0`, the sequence as a big-endian u64, then `event_id`, `timestamp`, `event_type`, `actor`, `prev_hash`, and the payload digest, each prefixed by its big-endian u64 byte length. The payload digest is SHA-256 over `argus.payload.v2\0` and the canonical payload. Signatures cover `argus.event.sig.v1\0` followed by the event hash. Format 1 joined fields with `:`, which let text move between adjacent fields without changing the hash; the Python package still verifies format-1 records written by earlier versions, and never writes them.

---

## Python: keyed signing (optional)

An unkeyed hash chain detects an edit to one record, but someone who can write the file can rewrite every later hash and still pass. Give the ledger a key and each event also carries an HMAC-SHA256 signature; the same rewrite then fails at the first forged event.

```python
from argus_ledger import AppendOnlyLedger

key = AppendOnlyLedger.load_key("/secure/location/argus.key")   # refuses a key file others can read
ledger = AppendOnlyLedger("audit.jsonl", signing_key=key, require_signature=True)
ledger.append("tool_execution", "agent", {"tool": "terminal"})
assert ledger.verify_chain().valid
```

The ledger file is created owner-only (0600). Keep the key somewhere an attacker with write access to the ledger cannot also reach. Ledgers written without a key still verify without one; with a key configured, unsigned events fail.

`verify_chain(anchor=event.anchor())`, with the anchor stored outside the writer's reach, also detects truncation, rollback, and a recomputed history. Ledgers written by earlier versions keep verifying: their records parse as hash format 1, `report.legacy_events` counts them, and new events continue the same chain in format 2.

## Benchmark results

Measured on bare-metal Linux x86_64 (`rustc 1.85.0`, `opt-level = 3`, `lto = "fat"`) with the `telarch-benchmarks` suite, which vendors the 0.1.0-alpha.3 crate (before payload validation and hash format 2):

| Metric | Measurement | Test condition | Operational Guarantee |
| :--- | :--- | :--- | :--- |
| **Append Throughput (1M Events)** | **632,170 events/s** | 1,000,000 sequential events (`argus_1m_scale`) | 1.58 &micro;s / event continuous SHA-256 chaining |
| **Linear Verification (1M Events)** | **770,758 events/s** | Full 1M event SHA-256 hash chain validation | 1.30 &micro;s / event; validates 1M events in 1.29 s |
| **Tamper Detection (Sequence #500,000)** | **640.48 ms** | Mid-chain single-bit payload corruption | Fail-closed immediate abort and offset isolation |
| **Micro-Audit Latency (Block #42)** | **46.50 &micro;s** | Short sequence microbenchmark | Sub-50 µs early tamper detection |
| **Tamper Detection Sensitivity** | **100.00%** | Single-bit byte flip sensitivity | Any single-bit change to a hashed field is detected |
| **External Dependencies** | **0** | Standalone offline primitives | Zero network, zero remote cloud requirement |

Run benchmarks yourself:

```bash
cargo run --release -p telarch-benchmarks
cargo run --release -p telarch-benchmarks --bin argus_1m_scale
```

---

## License

Copyright &copy; 2026 Perseus Computing LLC. Released under the [MIT License](LICENSE).
