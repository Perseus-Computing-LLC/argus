# Argus

**A record of what your agent did that shows if anyone changed it.** Argus appends every action to a linear SHA-256 hash chain. Verification names the first edited event, and checking against an anchor kept elsewhere catches a history that was rewritten from start to finish.

[![CI](https://github.com/Perseus-Computing-LLC/argus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Perseus-Computing-LLC/argus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-informational.svg)](Cargo.toml)

Argus is one of the three [Telarch](https://telarch.ai) libraries from [Perseus Computing LLC](https://perseuscomputing.com). [Harpe](https://github.com/Perseus-Computing-LLC/harpe) decides what goes into each model call, and [Kibisis](https://github.com/Perseus-Computing-LLC/kibisis) keeps the agent's memory. Each one works on its own. The crate and the Python package are published as `argus-ledger`.

## Why

Agents run commands, call APIs and edit files. Afterwards the log is the only account of what happened, and an ordinary log can be edited without a trace. Argus makes the edit visible and tells you where it is.

## What you get

- **Edits found, with their position.** Verification walks the chain and reports the first event whose hash or link does not check out.
- **Anchors for full rewrites.** Keep the latest sequence number and hash somewhere the writer cannot change. Verifying against that anchor catches a history that was rewritten, rolled back or truncated.
- **Optional signatures.** With a signing key, each event also carries an HMAC-SHA256 or Ed25519 signature that verification checks.
- **Local storage.** Both the Rust crate (`FileLedger`) and the Python package (`AppendOnlyLedger`) write a JSON Lines file under a POSIX file lock with `0600` permissions and `sync_data` durability. The Rust crate additionally provides `InMemoryLedger`.
- **No network code.** The ledger runs locally and sends nothing anywhere.

## Install

This README describes 0.1.0-alpha.8 (0.1.0a8 on PyPI). It is a pre-release, so name the version.

```toml
# Rust: Cargo.toml
[dependencies]
argus-ledger = "0.1.0-alpha.8"
```

```bash
# Python
pip install argus-ledger==0.1.0a8
```

## Quickstart

### Rust

```rust
use argus_ledger::{AuditLedgerWriter, AuditVerifier, InMemoryLedger, VerificationPolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = InMemoryLedger::new();
    ledger.append("tool.call", "agent_1", r#"{"command":"cargo test","tool":"bash"}"#)?;
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

Try it without installing anything: [telarch.ai/argus](https://telarch.ai/argus) runs the crate in your browser. Edit an event and watch verification stop at it.

## Measured

Medians of five runs of [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) v0.1.0-alpha.8, built against argus-ledger 0.1.0-alpha.5, with synthetic data on one EC2 m8azn.metal-12xl bare-metal server. Every run, its range and the command that reproduces it are on [telarch.ai/evidence](https://telarch.ai/evidence).

| Measurement | Result |
| --- | --- |
| Appends per second, 1,000,000 events, `InMemoryLedger` (no file, no fsync) | 1,113,765 |
| Events verified per second, full walk over events already parsed in memory | 3,110,589 |
| Time to find an edit at event 500,000, events already parsed in memory | 155.4 ms |
| A fully re-hashed history passes a check without an anchor | yes |
| The same history is caught by the anchor | yes |

These are in-memory figures. They do not include opening and parsing a ledger file, and the
append figure does not include durable storage. A durable append (`FileLedger` in Rust,
`AppendOnlyLedger` in Python) syncs every record to disk and runs at the storage device's
fsync rate, on the order of a thousand appends per second on typical SSDs. `argus-verify`
reports end-to-end time (open, parse and verify) for a file; expect it to be several times
lower than the verify-phase-only figure above because parsing dominates.

## How it works

- **Linear SHA-256 hash chain.** Each event's hash covers its sequence number, event ID, timestamp, event type, actor, the previous event's hash and a digest of its canonical JSON payload (`compute_event_hash` in `src/argus_ledger/hasher.py`; `src/lib.rs`).
- **Tamper detection.** `verify_chain` walks the chain from genesis and reports the first sequence whose hash or link does not check out (`first_broken_sequence`, `src/argus_ledger/ledger.py`).
- **Anchors and signatures.** Verifying against an anchor, a sequence number and hash kept outside the ledger, catches a ledger that was rewritten and re-hashed from genesis. With a signing key, each event also carries an HMAC-SHA256 or Ed25519 signature that verification checks (`src/argus_ledger/hasher.py`, `src/argus_ledger/ledger.py`; Rust: `VerificationPolicy` in `src/lib.rs`). To check an Ed25519-signed ledger without its private key, open it with `AppendOnlyLedger(path, verify_key=public_key)`: it checks Ed25519 signatures only and cannot append. Never pass a public key as `signing_key`, which is an HMAC secret: anyone who knows the public key could then sign events.
- **Timestamps and historic ledgers.** Every verifier requires each event's timestamp to be strictly after its predecessor's when compared as instants, so a replayed or back-dated record cannot be spliced in. Ledgers written before that rule existed can contain records whose timestamp is equal to or earlier than the one before (a host clock stepping backwards; the Python writer now prevents this). Such a ledger fails strict verification at the first regression even though every hash and link is intact. To accept those records as historic, pass a cutoff sequence: `argus-verify --legacy-timestamps-before <seq> audit.jsonl`, `ledger.verify_chain(legacy_timestamps_before=seq)` in Python, or `VerificationPolicy { legacy_timestamps_before: Some(seq), ..Default::default() }` in Rust. Below the cutoff a timestamp regression is counted (`legacy_timestamp_regressions`) and reported once as a warning (`warnings` in the report and in `argus-verify --json`, plus one stderr line) instead of failing the chain; hashes, `prev_hash` links, sequence continuity, malformed timestamps and malformed lines stay strict everywhere, and the strict timestamp rule applies from the cutoff onwards. The cutoff must be at least 1. Choose the smallest cutoff that passes, record it with the ledger, and treat any later regression as a finding. See [issue #14](https://github.com/Perseus-Computing-LLC/argus/issues/14).

## Limits

- **Alpha release:** APIs and formats are subject to revision before 1.0.
- **Detection, not prevention:** Argus cannot stop someone with write access from editing storage. It makes the edit visible.
- **Linear chain:** Verification reads every event, so it takes time proportional to the ledger's length, and there are no inclusion proofs for single events.
- **Anchoring requirement:** An unanchored chain that is rewritten and re-hashed from genesis is internally consistent. Keep the latest sequence number and hash somewhere the writer cannot change, and verify against it, to detect a complete rewrite.
- **Storage scope:** The Rust crate provides `InMemoryLedger` and `FileLedger`. The Python package writes a local JSONL file locked with `fcntl`, so it runs on Linux and macOS, not Windows.
- **Not independently assessed:** No security review or certification has been completed. Designed for local and disconnected use.
- **`argus_ledger.proofweave` is experimental:** the policy/evidence binding helpers may change or be removed before 1.0. `RAGTriadBinding.to_payload_dict()` emits float scores, which the ledger refuses; convert scores to integers (basis points) before appending.

## Security

Report a vulnerability to contact@perseuscomputing.com with `[SECURITY]` in the subject; please do not open a public issue. See the [security policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md) for response times.

## Links

- [telarch.ai/argus](https://telarch.ai/argus): overview and a live demo
- [Documentation (docs.rs)](https://docs.rs/argus-ledger)
- [Changelog](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
