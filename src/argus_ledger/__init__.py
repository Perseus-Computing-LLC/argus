"""argus-ledger: Tamper-evident append-only SHA-256 provenance and audit ledger for autonomous agents."""

from .models import AuditEvent, ChainAnchor, ChainVerificationReport, CURRENT_HASH_VERSION, GENESIS_PREV_HASH
from .canonical import canonical_json_bytes, canonical_json_dumps, FloatPayloadError, reject_float_payload
from .hasher import (
    SIGNATURE_DOMAIN,
    compute_event_hash,
    compute_payload_digest,
    ed25519_public_key,
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
from .proofweave import (
    AgentTraceBinding,
    MerkleMountainRange,
    PolicyActionBinding,
    PraxaGovernanceGovernor,
    PraxaState,
    ProofWeaveTransaction,
    RAGTriadBinding,
)

__version__ = "0.1.0a7"

__all__ = [
    "FloatPayloadError",
    "reject_float_payload",
    "AuditEvent",
    "ChainVerificationReport",
    "GENESIS_PREV_HASH",
    "PolicyActionBinding",
    "AgentTraceBinding",
    "RAGTriadBinding",
    "ProofWeaveTransaction",
    "PraxaGovernanceGovernor",
    "PraxaState",
    "MerkleMountainRange",
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
    "ChainAnchor",
    "CURRENT_HASH_VERSION",
    "SIGNATURE_DOMAIN",
    "compute_payload_digest",
    "ed25519_public_key",
]
