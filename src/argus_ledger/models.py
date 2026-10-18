"""Data models for Argus append-only audit ledger."""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

GENESIS_PREV_HASH = "0" * 64

# Event hash format written by this version. Format 2 length-prefixes every field under a domain
# tag (byte-identical to the Rust crate); format 1 joined fields with ':' and is verify-only.
CURRENT_HASH_VERSION = 2


class AuditEvent(BaseModel):
    """An individual tamper-evident audit event with cryptographic hash chaining."""
    sequence: int = Field(ge=1, description="1-indexed monotonic sequence number.")
    event_id: str = Field(description="Unique event ID (UUID/ULID).")
    timestamp: str = Field(description="ISO-8601 UTC timestamp of event creation.")
    event_type: str = Field(description="Event type classifier (e.g. tool.exec, memory.write).")
    actor: str = Field(description="Actor or agent identifier producing the event.")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event payload.")
    prev_hash: str = Field(description="SHA-256 hash of the preceding event (or 64 zeros for genesis).")
    event_hash: str = Field(description="SHA-256 hash of this event.")
    signature: Optional[str] = Field(default=None, description="Optional cryptographic signature.")
    hash_version: int = Field(
        default=1,
        ge=1,
        le=CURRENT_HASH_VERSION,
        description=(
            "Hash and signature format of this record. Records written before the field existed "
            "parse as 1 (legacy ':'-joined preimage, untagged signatures); new records are 2."
        ),
    )

    def anchor(self) -> "ChainAnchor":
        """Commitment to this event's chain position, for publication to an external witness."""
        return ChainAnchor(sequence=self.sequence, event_hash=self.event_hash)


class ChainAnchor(BaseModel):
    """Externally witnessed commitment to one chain position, such as a head hash published to a
    transparency log or held by another trust domain. It is evidence only if the ledger's writer
    cannot rewrite the place it was obtained from."""
    sequence: int = Field(ge=1, description="Sequence number of the witnessed event.")
    event_hash: str = Field(description="event_hash of the witnessed event.")


class ChainVerificationReport(BaseModel):
    """Verification report evaluating hash-chain integrity across audit events."""
    valid: bool = Field(description="Whether the entire hash chain is valid and unbroken.")
    total_events: int = Field(ge=0, description="Total number of events evaluated.")
    root_hash: str = Field(description="Hash of the genesis event (or empty if zero events).")
    head_hash: str = Field(description="Hash of the latest event in the chain.")
    first_broken_sequence: Optional[int] = Field(default=None, description="Sequence of first invalid event if broken.")
    error_detail: Optional[str] = Field(default=None, description="Detailed diagnosis if chain is broken.")
    checked_at: str = Field(description="ISO-8601 timestamp of when verification was performed.")
    legacy_events: int = Field(
        default=0,
        ge=0,
        description="Events verified under hash format 1, whose field boundaries are not bound into the hash.",
    )
    anchored: bool = Field(
        default=False,
        description="True if the chain was checked against an external anchor (detects rollback and rewrites up to it).",
    )
