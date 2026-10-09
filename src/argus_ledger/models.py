"""Data models for Argus append-only audit ledger."""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

GENESIS_PREV_HASH = "0" * 64


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


class ChainVerificationReport(BaseModel):
    """Verification report evaluating hash-chain integrity across audit events."""
    valid: bool = Field(description="Whether the entire hash chain is valid and unbroken.")
    total_events: int = Field(ge=0, description="Total number of events evaluated.")
    root_hash: str = Field(description="Hash of the genesis event (or empty if zero events).")
    head_hash: str = Field(description="Hash of the latest event in the chain.")
    first_broken_sequence: Optional[int] = Field(default=None, description="Sequence of first invalid event if broken.")
    error_detail: Optional[str] = Field(default=None, description="Detailed diagnosis if chain is broken.")
    checked_at: str = Field(description="ISO-8601 timestamp of when verification was performed.")
