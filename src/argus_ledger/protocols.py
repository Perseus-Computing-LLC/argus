"""Interface protocols for Argus append-only audit ledger."""

from __future__ import annotations

from typing import Any, Dict, Iterator, Optional, Protocol, runtime_checkable
from .models import AuditEvent, ChainAnchor, ChainVerificationReport


class LedgerError(Exception):
    """Base exception for ledger operations."""
    pass


class TamperDetectedError(LedgerError):
    """Raised when ledger verification detects hash mismatch or chain tampering."""
    pass


class LedgerCorruptionError(LedgerError):
    """Raised when the ledger file contains malformed JSON or partial-write corruption."""
    pass


@runtime_checkable
class AuditLedgerWriter(Protocol):
    """Writer interface for appending audit events."""

    def append(
        self,
        event_type: str,
        actor: str,
        payload: Dict[str, Any],
        event_id: Optional[str] = None,
    ) -> AuditEvent:
        """Append an event to the ledger with hash chaining."""
        ...


@runtime_checkable
class AuditLedgerReader(Protocol):
    """Reader interface for inspecting audit events."""

    def get_event(self, sequence: int) -> Optional[AuditEvent]:
        """Fetch event by sequence number."""
        ...

    def iter_events(self, start: int = 1, end: Optional[int] = None) -> Iterator[AuditEvent]:
        """Iterate events within sequence range."""
        ...

    def head(self) -> Optional[AuditEvent]:
        """Return the latest event in the chain."""
        ...

    @property
    def head_hash(self) -> Optional[str]:
        """Event hash of the latest event in the chain."""
        ...


@runtime_checkable
class AuditVerifier(Protocol):
    """Verifier interface for validating hash chain continuity."""

    def verify_chain(
        self,
        anchor: Optional[ChainAnchor] = None,
        legacy_timestamps_before: Optional[int] = None,
    ) -> ChainVerificationReport:
        """Traverse the entire ledger and verify SHA-256 hash continuity and integrity. Without an
        anchor (an externally kept ``AuditEvent.anchor()``) this proves internal consistency only.
        ``legacy_timestamps_before`` accepts timestamp regressions below that sequence as historic
        (issue #14); see ``AppendOnlyLedger.verify_chain``."""
        ...
