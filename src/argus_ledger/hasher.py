"""Cryptographic hashing and verification functions for audit events."""

from __future__ import annotations

import hashlib
from typing import Any, Dict
from .canonical import canonical_json_bytes
from .models import AuditEvent


def compute_event_hash(
    sequence: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    actor: str,
    prev_hash: str,
    payload: Dict[str, Any],
) -> str:
    """Compute the deterministic SHA-256 hash for an audit event."""
    header = f"{sequence}:{event_id}:{timestamp}:{event_type}:{actor}:{prev_hash}:"
    header_bytes = header.encode("utf-8")
    payload_bytes = canonical_json_bytes(payload)

    hasher = hashlib.sha256()
    hasher.update(header_bytes)
    hasher.update(payload_bytes)
    return hasher.hexdigest()


def verify_event(event: AuditEvent) -> bool:
    """Verify that an event's hash matches its contents."""
    expected_hash = compute_event_hash(
        sequence=event.sequence,
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        actor=event.actor,
        prev_hash=event.prev_hash,
        payload=event.payload,
    )
    return event.event_hash == expected_hash
