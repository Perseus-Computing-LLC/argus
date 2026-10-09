"""argus-ledger: Tamper-evident append-only SHA-256 provenance and audit ledger for autonomous agents."""

from .models import AuditEvent, ChainVerificationReport, GENESIS_PREV_HASH
from .canonical import canonical_json_bytes, canonical_json_dumps
from .hasher import compute_event_hash, verify_event
from .protocols import (
    AuditLedgerReader,
    AuditLedgerWriter,
    AuditVerifier,
    LedgerError,
    TamperDetectedError,
)
from .ledger import AppendOnlyLedger

__version__ = "0.1.0a1"

__all__ = [
    "AuditEvent",
    "ChainVerificationReport",
    "GENESIS_PREV_HASH",
    "canonical_json_bytes",
    "canonical_json_dumps",
    "compute_event_hash",
    "verify_event",
    "AuditLedgerReader",
    "AuditLedgerWriter",
    "AuditVerifier",
    "LedgerError",
    "TamperDetectedError",
    "AppendOnlyLedger",
]
