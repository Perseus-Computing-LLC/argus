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

## Scope & Invariants
- Argus is an append-only provenance and audit ledger based on a linear SHA-256 hash chain.
- Invariant: Modifying or removing any historical event breaks SHA-256 continuity; `verify_chain` will identify and fail closed at the first affected event.
- Invariant: When verified against an authoritative `ChainAnchor` or signed checkpoint, full-chain rewrite attacks cannot evade detection.
- Invariant: Argus contains zero network code, telemetry, or remote dependencies.
