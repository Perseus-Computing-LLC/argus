"""argus-ledger: Tamper-evident append-only SHA-256 provenance and audit ledger for autonomous agents."""

from .models import AuditEvent, ChainVerificationReport, GENESIS_PREV_HASH
from .canonical import canonical_json_bytes, canonical_json_dumps
from .hasher import (
    compute_event_hash,
    sign_event_hash,
    sign_event_hash_ed25519,
    verify_event,
    verify_signature,
    verify_signature_ed25519,
)
from .protocols import (
    AuditLedgerReader,
    AuditLedgerWriter,
    AuditVerifier,
    LedgerCorruptionError,
    LedgerError,
    TamperDetectedError,
)
from .ledger import AppendOnlyLedger
from .proofweave import PolicyActionBinding

__version__ = "0.1.0a3"

__all__ = [
    "AuditEvent",
    "ChainVerificationReport",
    "GENESIS_PREV_HASH",
    "PolicyActionBinding",
    "canonical_json_bytes",
    "canonical_json_dumps",
    "compute_event_hash",
    "verify_event",
    "sign_event_hash",
    "sign_event_hash_ed25519",
    "verify_signature",
    "verify_signature_ed25519",
    "AuditLedgerReader",
    "AuditLedgerWriter",
    "AuditVerifier",
    "LedgerCorruptionError",
    "LedgerError",
    "TamperDetectedError",
    "AppendOnlyLedger",
]
