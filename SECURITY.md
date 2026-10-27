# Security Policy

Argus is part of the Telarch Suite by Perseus Computing LLC.

## Reporting a Vulnerability

Please do not report security vulnerabilities via public GitHub issues.

Send details directly to:
**`contact@perseuscomputing.com`**
Subject: `[SECURITY] Argus Vulnerability Report`

### SLA
- **Acknowledgement**: Within 48 hours.
- **Triage & Status**: Within 5 business days.
- **Fix & Advisory**: Within 14 calendar days for verified high/critical vulnerabilities.

## Known issues and notes

### 2026-10-27 — alpha.6 `argus-verify` could not verify float payloads written by the Python library
`argus-verify` 0.1.0-alpha.6 reported an event-hash mismatch on a record whose payload held a 16-digit
float written by the Python writer (`-9.865914147294541`); serde_json's default parser read it inexactly,
so the recomputed payload digest differed. The Python verifier accepted the same ledger. Impact: an
independent (Rust) verification of such a ledger failed when it should have passed; no record could be
altered or forged by this. Fixed in 0.1.0-alpha.7: the verifier parses floats correctly rounded
(`float_roundtrip`) and the Python writer refuses floats at `append()`, as the Rust writer already did.
Operators who anchored a ledger with alpha.6 should re-verify with alpha.7; the anchors themselves are
unaffected. Details: CHANGELOG 0.1.0-alpha.7.

## Scope
- Argus records events in a linear SHA-256 hash chain. It runs inside your process and has no network code or telemetry.
- Verification checks sequence numbers, hash links and event hashes, and signatures when given a key. It reports the first broken position (`first_broken_sequence`).
- Without an anchor, verification proves internal consistency only: an empty or truncated chain passes, and so does one recomputed by someone who can write the log. Signing events with a key stops recomputation by anyone without the key. Keeping a `ChainAnchor` (the sequence number and hash of a recent event) where the writer cannot change it also detects rollback, truncation below the anchor and history rewritten up to it.
- Argus does not implement a checkpoint format. Storing anchors outside the ledger is up to you.
