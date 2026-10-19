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

## Scope
- Argus records events in a linear SHA-256 hash chain. It runs inside your process and has no network code or telemetry.
- Verification checks sequence numbers, hash links and event hashes, and signatures when given a key. It reports the first broken position (`first_broken_sequence`).
- Without an anchor, verification proves internal consistency only: an empty or truncated chain passes, and so does one recomputed by someone who can write the log. Signing events with a key stops recomputation by anyone without the key. Keeping a `ChainAnchor` (the sequence number and hash of a recent event) where the writer cannot change it also detects rollback, truncation below the anchor and history rewritten up to it.
- Argus does not implement a checkpoint format. Storing anchors outside the ledger is up to you.
