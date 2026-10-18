# Telarch Claims & Benchmark Audit Ledger

> In accordance with Telarch engineering principles and the Agent Memory Atlas methodology, all architectural claims and benchmark figures in Telarch documentation must correspond to committed, runnable code with deterministic verification paths. Unsubstantiated claims are formally retired.

---

## 1. Retired & Corrected Claims

The following claims previously present in documentation or legacy monolithic materials have been audited and formally retired or corrected:

| Component | Previous Claim | Disposition | Ground Truth & Correction |
| :--- | :--- | :--- | :--- |
| **External Evaluations** | LongMemEval-S 0.9111 MRR across 23,854 sessions | **RETIRED** | Standalone runner and multi-seed run reports are not yet committed to `telarch-benchmarks`. Historical monolithic runs achieved 73.8% (vanilla) and 79.0% (official-cot), but all headline metrics are withdrawn from READMEs until the modular harness and 3-seed artifacts are committed. |
| **Kibisis Crypto** | ChaCha20-Poly1305 with Argon2id | **CORRECTED** | Codebase implements AES-256-GCM authenticated encryption with PBKDF2HMAC-SHA256 (600,000 iterations for new envelopes; 100,000 legacy compatibility). Documentation updated to reflect the actual cipher suite. |
| **Kibisis Storage** | Envelope encryption claimed in docs | **REMEDIATED** | Previous `SQLiteMemoryVault` stored plaintext in `entities` and `entities_fts` without calling `AESGCMCryptoEnvelopeProvider`. Wire-level envelope encryption has now been integrated directly into the `put()` / `get()` storage path with FTS cleartext suppression. |
| **Kibisis Tombstones**| Exact SHA-256 hash matching | **REMEDIATED** | Exact-match hashing allowed trivial bypass via casing/punctuation changes. Upgraded to canonicalized text normalization (Unicode NFKC, lowercase folding, punctuation removal, whitespace collapse). |
| **Argus Latency** | 4.12 µs append latency | **CORRECTED** | Measured bare-metal throughput is ~600,000 events/s (~1.67 µs/op) for in-memory SHA-256 event chaining. |
| **Argus Verification**| 2,170,000 events/s verification | **CORRECTED** | 2.17M was a copy-paste artifact from Kibisis in-memory ingestion. Measured full-chain validation traversal is ~839,000 events/s (~1.19 µs/event). |
| **Argus Tamper** | Scans 100,000 events in 46.00 µs | **CORRECTED** | The 46.50 µs metric represents immediate fail-closed abort upon detecting tampered block #42 in sequence, not a full 100,000-block traversal. |
| **Argus Integrity** | Altered or deleted entries always fail verification | **CORRECTED** | Without an external anchor, verification proves internal consistency only: removing the newest events, an emptied ledger, and a recomputed chain all pass. Anchored verification (`verify_chain_with` + `ChainAnchor` in Rust, `verify_chain(anchor=...)` in Python) or signature checks close these cases. "Mathematical immutability guarantee" replaced by the measured property (single-bit changes to hashed fields are detected). |
| **Argus Hash Format** | SHA-256 binds every event field | **REMEDIATED** | The `:`-joined preimage let text move between adjacent fields (for example `event_type` into `actor`) without changing the hash. Hash format 2 length-prefixes every field under a domain tag, identical in Rust and Python and pinned by shared golden vectors; Python verifies format-1 records from earlier versions and never writes them. |
| **Argus Signatures** | Signed events cannot be forged without the key | **REMEDIATED** | Rust never signed appended events or checked signatures during verification, and both implementations accepted small-order Ed25519 public keys (an identity key verifies a forged `R = identity, S = 0` signature for every message) and non-canonical signature hex. Rust now signs on append and uses `verify_strict`; Python rejects small-order keys and `R` points and non-canonical hex; both domain-separate signatures. |

---

## 2. Active Verified Claims Matrix

All metrics below are reproducible via `cargo run --release -p telarch-benchmarks` on bare-metal Linux x86_64. The Argus rows were measured on the 0.1.0-alpha.3 crate the benchmark suite vendors (before payload validation and hash format 2) and need re-measurement once the suite vendors the hardened crate:

| System | Metric | Target / Claim | Verification Command | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Harpe** | Small Context (10 items, 60-token budget) | p50: ~1.88 µs | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | Large Context (200 items, 1,500-token budget) | p50: ~41.16 µs | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | Multi-Turn Pruning Ceiling Reduction | ~69.51% reduction | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | 100,000-Turn Production Cost Curve | 78.28% reduction, 0 overruns, 46.9 µs/turn | `cargo run --release -p telarch-benchmarks --bin knapsack_cost_curve` | **VERIFIED** |
| **Kibisis** | Sequential In-Memory Write Ingestion (audit-journaled) | 271,222 writes/s | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Kibisis** | Multi-Agent SWMR Lease Concurrency (16 workers) | 1,466,471 ops/s (0.68 µs latency), 0 split-brain | `cargo run --release -p telarch-benchmarks --bin adversarial_contention` | **VERIFIED** |
| **Kibisis** | Multi-Agent SWMR Lease Concurrency (32 workers) | 1,597,354 ops/s (0.63 µs latency), 0 split-brain | `cargo run --release -p telarch-benchmarks --bin adversarial_contention` | **VERIFIED** |
| **Argus** | Append Through the Public API (1M events) | 809,698 events/s (1.24 µs/op) | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Argus** | Full Chain Verification (1M events) | 2,433,053 events/s (0.41 µs/event) | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Argus** | Tamper Fail-Closed Detection (Sequence #500,000) | 185.35 ms across 1M events | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Swarm** | Network Partition Tolerance (50% drop) | 100% convergence, 0 split-brain (264,971 msgs/s) | `cargo run --release -p telarch-benchmarks --bin swarm_partition` | **VERIFIED** |
| **Payload** | Tier 0 / Tier 1 Restricted Payloads | 93.6% / 88.7% reduction (<32 µs) | `cargo run --release -p telarch-benchmarks --bin restricted_payload_test` | **VERIFIED** |

---

## 3. Cryptographic & Negative Memory Guarantees

1. **Storage-Engine Encryption**:
   * Algorithm: AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
   * Key Derivation: PBKDF2HMAC with SHA-256, 600,000 iterations for new envelopes (envelopes written before this field existed carry 100,000 and still decrypt); one 16-byte random salt per vault, a fresh 12-byte nonce per entry.
   * SQLite Storage: Encrypted payloads stored as authenticated binary envelopes (`ciphertext`, `nonce`, `salt`, `algo`).
   * Plaintext Leakage Prevention: When encryption is active, raw content is never inserted into unencrypted FTS5 virtual tables.

2. **Negative Memory Tombstones**:
   * Normalization: Unicode NFKC normalization $\rightarrow$ lowercase fold $\rightarrow$ punctuation strip $\rightarrow$ whitespace collapse.
   * Matching: Content matches against normalized rejection digests and canonical tokens, preventing trivial prompt injection or typographical evasion.
