"""Append-only audit ledger implementation with file locking and hash chaining."""

from __future__ import annotations

import datetime
import fcntl
import json
import os
import uuid
from typing import Any, Dict, Iterator, List, Optional
from .hasher import compute_event_hash, sign_event_hash, verify_event, verify_signature
from .models import AuditEvent, ChainVerificationReport, GENESIS_PREV_HASH
from .protocols import AuditLedgerReader, AuditLedgerWriter, AuditVerifier, LedgerCorruptionError


class AppendOnlyLedger(AuditLedgerWriter, AuditLedgerReader, AuditVerifier):
    """Append-only audit ledger backed by a JSON-L file with POSIX file locking."""

    def __init__(
        self,
        ledger_path: str,
        signing_key: Optional[bytes] = None,
        *,
        require_signature: bool = False,
        use_ed25519: bool = False,
    ) -> None:
        """``signing_key``: when set, every event is signed with HMAC-SHA256 (or Ed25519 if use_ed25519=True),
        and verification fails for an event whose signature is missing or wrong.
        Rewriting the whole chain then needs the key, not just the file.
        ``require_signature=True`` refuses to open without a key. The ledger file is created owner-only (0600)."""
        if require_signature and not signing_key:
            raise ValueError("require_signature=True needs a signing_key")
        if signing_key is not None and len(signing_key) < 16:
            raise ValueError("signing_key must be at least 16 bytes")
        if use_ed25519:
            if signing_key is None or len(signing_key) != 32:
                raise ValueError("use_ed25519=True requires a 32-byte Ed25519 seed/private key")
        self._key = signing_key
        self._use_ed25519 = use_ed25519
        self.ledger_path = os.path.abspath(ledger_path)
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        if not os.path.exists(self.ledger_path):
            fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)

    @staticmethod
    def load_key(path: str) -> bytes:
        """Read a signing key from a file that only its owner can access."""
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"Key file {path} is readable by group or others (mode {mode:o}); chmod 600 it.")
        with open(path, "rb") as fh:
            return fh.read().strip()

    def append(
        self,
        event_type: str,
        actor: str,
        payload: Dict[str, Any],
        event_id: Optional[str] = None,
    ) -> AuditEvent:
        eid = event_id or str(uuid.uuid4())
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with open(self.ledger_path, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                lines = [line.strip() for line in f if line.strip()]

                if not lines:
                    sequence = 1
                    prev_hash = GENESIS_PREV_HASH
                else:
                    try:
                        last_obj = json.loads(lines[-1])
                        sequence = int(last_obj["sequence"]) + 1
                        prev_hash = str(last_obj["event_hash"])
                    except (ValueError, KeyError, TypeError) as exc:
                        raise LedgerCorruptionError(
                            f"Cannot append to ledger with corrupted tail record at line {len(lines)}: {exc}"
                        ) from exc

                event_hash = compute_event_hash(
                    sequence=sequence,
                    event_id=eid,
                    timestamp=now_ts,
                    event_type=event_type,
                    actor=actor,
                    prev_hash=prev_hash,
                    payload=payload,
                )

                if self._key:
                    if self._use_ed25519:
                        from .hasher import sign_event_hash_ed25519
                        sig = sign_event_hash_ed25519(event_hash, self._key)
                    else:
                        sig = sign_event_hash(event_hash, self._key)
                else:
                    sig = None

                event = AuditEvent(
                    sequence=sequence,
                    event_id=eid,
                    timestamp=now_ts,
                    event_type=event_type,
                    actor=actor,
                    payload=payload,
                    prev_hash=prev_hash,
                    event_hash=event_hash,
                    signature=sig,
                )

                f.seek(0, os.SEEK_END)
                f.write(event.model_dump_json() + "\n")
                f.flush()
                os.fsync(f.fileno())
                return event
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def head(self) -> Optional[AuditEvent]:
        if not os.path.exists(self.ledger_path):
            return None

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    return None
                try:
                    return AuditEvent.model_validate_json(lines[-1])
                except Exception as exc:
                    raise LedgerCorruptionError(
                        f"Malformed tail event record at line {len(lines)}: {exc}"
                    ) from exc
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def get_event(self, sequence: int) -> Optional[AuditEvent]:
        for event in self.iter_events():
            if event.sequence == sequence:
                return event
        return None

    def iter_events(self, start: int = 1, end: Optional[int] = None) -> Iterator[AuditEvent]:
        if not os.path.exists(self.ledger_path):
            return

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = AuditEvent.model_validate_json(line)
                    except Exception as exc:
                        raise LedgerCorruptionError(
                            f"Malformed event record at line {line_no}: {exc}"
                        ) from exc
                    if event.sequence < start:
                        continue
                    if end is not None and event.sequence > end:
                        break
                    yield event
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def verify_chain(self) -> ChainVerificationReport:
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if not os.path.exists(self.ledger_path):
            return ChainVerificationReport(
                valid=True,
                total_events=0,
                root_hash="",
                head_hash="",
                checked_at=now_ts,
            )

        events: List[AuditEvent] = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                raw_lines = [line.strip() for line in f if line.strip()]
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        if not raw_lines:
            return ChainVerificationReport(
                valid=True,
                total_events=0,
                root_hash="",
                head_hash="",
                checked_at=now_ts,
            )

        for idx, line in enumerate(raw_lines, start=1):
            try:
                events.append(AuditEvent.model_validate_json(line))
            except Exception as exc:
                root_hash = events[0].event_hash if events else ""
                head_hash = events[-1].event_hash if events else ""
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(raw_lines),
                    root_hash=root_hash,
                    head_hash=head_hash,
                    first_broken_sequence=idx,
                    error_detail=f"Malformed or partial event record at sequence {idx}: {exc}",
                    checked_at=now_ts,
                )

        expected_prev = GENESIS_PREV_HASH
        for idx, event in enumerate(events, start=1):
            if event.sequence != idx:
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(events),
                    root_hash=events[0].event_hash,
                    head_hash=events[-1].event_hash,
                    first_broken_sequence=event.sequence,
                    error_detail=f"Sequence discontinuity: expected {idx}, found {event.sequence}",
                    checked_at=now_ts,
                )

            if event.prev_hash != expected_prev:
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(events),
                    root_hash=events[0].event_hash,
                    head_hash=events[-1].event_hash,
                    first_broken_sequence=event.sequence,
                    error_detail=f"Broken prev_hash at sequence {event.sequence}: expected {expected_prev}, got {event.prev_hash}",
                    checked_at=now_ts,
                )

            if not verify_event(event):
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(events),
                    root_hash=events[0].event_hash,
                    head_hash=events[-1].event_hash,
                    first_broken_sequence=event.sequence,
                    error_detail=f"Tampered payload or signature at sequence {event.sequence}",
                    checked_at=now_ts,
                )

            if self._key is not None and not verify_signature(event, self._key):
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(events),
                    root_hash=events[0].event_hash,
                    head_hash=events[-1].event_hash,
                    first_broken_sequence=event.sequence,
                    error_detail=f"Missing or invalid signature at sequence {event.sequence}",
                    checked_at=now_ts,
                )

            expected_prev = event.event_hash

        return ChainVerificationReport(
            valid=True,
            total_events=len(events),
            root_hash=events[0].event_hash,
            head_hash=events[-1].event_hash,
            checked_at=now_ts,
        )
