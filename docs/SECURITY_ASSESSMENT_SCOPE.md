# Argus External Cryptographic & Security Assessment Scope

This document specifies the target evaluation charter, verification invariants, and threat model for independent third-party security assessments of Argus.

## 1. Context & Control Mapping Policy

Argus documentation and specifications explicitly state:
> **Not independently assessed:** No security review or certification has been completed. Designed for local and disconnected use.

Until an independent audit by a qualified external cryptographic security evaluator is completed, Argus makes **no claims of compliance** with statutory or regulatory frameworks (such as NIST SP 800-53 AU-2 / AU-3, FedRAMP, or ISO/IEC 27001). Any compliance or readiness positioning is limited strictly to architectural alignment ("designed to support") rather than certification ("satisfies").

---

## 2. External Audit Scope & Technical Focus Areas

Independent security reviewers should audit the following four core subsystems:

### A. Canonicalization Equivalence (`canonical.py` vs. Rust Serde)
- **Objective:** Ensure bit-exact canonical JSON serialization across both implementations for identical abstract structures.
- **Invariants:**
  - Strict UTF-8 serialization without ASCII escaping.
  - Lexicographically sorted dictionary keys by Unicode codepoints.
  - Compact separators (`","` and `":"`, zero unnecessary whitespace).
  - Explicit rejection of `NaN`, `Infinity`, and unquoted floating-point edge cases.
- **Reference Code:** `src/argus_ledger/canonical.py` (Python) and `src/canonical.rs` / `src/lib.rs` (Rust).

### B. Anchor and Checkpoint Signing
- **Objective:** Evaluate the cryptographic integrity of out-of-band anchors and event signatures against forged history.
- **Invariants:**
  - Verification with an out-of-band anchor (`sequence` + `event_hash`) must detect any rewriting or re-hashing from genesis.
  - HMAC-SHA256 vs. Ed25519 signature policies (`VerificationPolicy` in Rust, `ledger.verify_chain` in Python).
  - Verification with a public key must disallow ledger append operations (preventing accidental key leakage).
- **Reference Code:** `src/argus_ledger/hasher.py`, `src/argus_ledger/ledger.py`, and `src/lib.rs`.

### C. Timestamp Monotonicity & Backward Clock Splicing
- **Objective:** Verify that historical timestamp verification resists replay and back-dated record splicing.
- **Invariants:**
  - Events must have timestamps strictly greater than their predecessor ($t_i > t_{i-1}$) evaluated as UTC instants.
  - Legacy cutoffs (`legacy_timestamps_before`) must require strict monotonicity from the cutoff sequence onwards while strictly maintaining hash chain continuity across all records.
- **Reference Code:** `src/argus_ledger/ledger.py` and `src/verification.rs`.

### D. Threat Model for Local Attackers with Raw File Write Access
- **Assumed Adversary:** An attacker possessing local operating-system privileges capable of directly writing, modifying, or truncating the raw `audit.jsonl` file.
- **Security Guarantees:**
  - Argus is a *tamper-evident* ledger, not a *write-prevention* hardware security module.
  - An attacker modifying any byte in an event must cause chain verification to fail at that sequence (`first_broken_sequence`).
  - An attacker attempting to regenerate hashes from the point of modification must fail verification when checked against any out-of-band anchor or signed checkpoint.
  - Concurrent writes must be coordinated via `fcntl` locking, preventing interleaved malformed lines from uncoordinated writers.

---

## 3. Prior Remediations (Reference)
- **F1 (Self-bricking writer):** Resolved in PR #13 by atomic transaction flush and lock recovery.
- **F2 (CLI parser line skipping):** Resolved in PR #14 by enforcing strict line-by-line JSON parsing and flagging any malformed or truncated line as a chain-breaking failure.
