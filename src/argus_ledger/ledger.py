"""Append-only audit ledger implementation with file locking and hash chaining."""

from __future__ import annotations

import datetime
import fcntl
import json
import os
import uuid
from typing import Any, Dict, Iterator, List, Optional
from .hasher import (
    compute_event_hash,
    ed25519_public_key,
    sign_event_hash,
    sign_event_hash_ed25519,
    verify_event,
    verify_signature,
    verify_signature_ed25519,
)
from .models import CURRENT_HASH_VERSION, AuditEvent, ChainAnchor, ChainVerificationReport, GENESIS_PREV_HASH
from .protocols import AuditLedgerReader, AuditLedgerWriter, AuditVerifier, LedgerCorruptionError

_TAIL_BLOCK = 1 << 16


def _tail_record(fd: int) -> Optional[bytes]:
    """The last non-blank line of the file open at ``fd``, read backwards: O(record), not O(file)."""
    pos = os.fstat(fd).st_size
    tail = b""
    while pos > 0:
        start = max(0, pos - _TAIL_BLOCK)
        tail = os.pread(fd, pos - start, start) + tail
        pos = start
        record = tail.rstrip()
        newline = record.rfind(b"\n")
        if record and (newline >= 0 or pos == 0):
            return record[newline + 1:].strip()
    return None


def _count_records(path: str) -> int:
    """Number of non-blank lines, for error messages only."""
    with open(path, "rb") as fh:
        return sum(1 for line in fh if line.strip())


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
        Rewriting the whole chain then needs the key, not just the file. A ledger opened with an
        Ed25519 public key as ``signing_key`` (and use_ed25519=False) verifies Ed25519 signatures.
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
        # Derived once: verification then needs one signature check per event, not a key derivation.
        self._ed25519_public_key = (
            ed25519_public_key(signing_key) if use_ed25519 and signing_key is not None else None
        )
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
                size = os.fstat(f.fileno()).st_size
                tail = _tail_record(f.fileno())

                if tail is None:
                    sequence = 1
                    prev_hash = GENESIS_PREV_HASH
                else:
                    try:
                        last_obj = json.loads(tail)
                        sequence = int(last_obj["sequence"]) + 1
                        prev_hash = str(last_obj["event_hash"])
                    except (ValueError, KeyError, TypeError) as exc:
                        raise LedgerCorruptionError(
                            "Cannot append to ledger with corrupted tail record at line "
                            f"{_count_records(self.ledger_path)}: {exc}"
                        ) from exc

                event_hash = compute_event_hash(
                    sequence=sequence,
                    event_id=eid,
                    timestamp=now_ts,
                    event_type=event_type,
                    actor=actor,
                    prev_hash=prev_hash,
                    payload=payload,
                    hash_version=CURRENT_HASH_VERSION,
                )

                if self._key:
                    if self._use_ed25519:
                        sig = sign_event_hash_ed25519(event_hash, self._key, hash_version=CURRENT_HASH_VERSION)
                    else:
                        sig = sign_event_hash(event_hash, self._key, hash_version=CURRENT_HASH_VERSION)
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
                    hash_version=CURRENT_HASH_VERSION,
                )

                # A record whose trailing newline was lost (torn write, manual edit) must not absorb
                # this one: both would become one malformed line.
                separator = "" if size == 0 or os.pread(f.fileno(), 1, size - 1) == b"\n" else "\n"
                f.seek(0, os.SEEK_END)
                f.write(separator + event.model_dump_json() + "\n")
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
                record = _tail_record(f.fileno())
                if record is None:
                    return None
                try:
                    return AuditEvent.model_validate_json(record)
                except Exception as exc:
                    raise LedgerCorruptionError(
                        f"Malformed tail event record at line {_count_records(self.ledger_path)}: {exc}"
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

    def _signature_valid(self, event: AuditEvent, key: bytes) -> bool:
        if self._ed25519_public_key is not None:
            return verify_signature_ed25519(event, self._ed25519_public_key)
        return verify_signature(event, key)

    def verify_chain(self, anchor: Optional[ChainAnchor] = None) -> ChainVerificationReport:
        """Verify sequence numbers, hash links, event hashes and, with a key, signatures.

        Without ``anchor`` this proves internal consistency only: an empty, truncated or fully
        recomputed chain passes, and only a key stops someone who can write the file from
        recomputing it. ``anchor`` (``AuditEvent.anchor()`` kept where the writer cannot change it)
        also detects rollback, truncation below the anchor and rewritten history up to it.
        ``first_broken_sequence`` is the chain position, never a value read from the record."""
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        anchored = anchor is not None

        raw_lines: List[str] = []
        if os.path.exists(self.ledger_path):
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    raw_lines = [line.strip() for line in f if line.strip()]
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        events: List[AuditEvent] = []
        for idx, line in enumerate(raw_lines, start=1):
            try:
                events.append(AuditEvent.model_validate_json(line))
            except Exception as exc:
                return ChainVerificationReport(
                    valid=False,
                    total_events=len(raw_lines),
                    root_hash=events[0].event_hash if events else "",
                    head_hash=events[-1].event_hash if events else "",
                    first_broken_sequence=idx,
                    error_detail=f"Malformed or partial event record at sequence {idx}: {exc}",
                    checked_at=now_ts,
                    anchored=anchored,
                )

        root_hash = events[0].event_hash if events else ""
        head_hash = events[-1].event_hash if events else ""
        legacy_events = 0

        def broken(position: int, detail: str) -> ChainVerificationReport:
            return ChainVerificationReport(
                valid=False,
                total_events=len(events),
                root_hash=root_hash,
                head_hash=head_hash,
                first_broken_sequence=position,
                error_detail=detail,
                checked_at=now_ts,
                legacy_events=legacy_events,
                anchored=anchored,
            )

        expected_prev = GENESIS_PREV_HASH
        newest_version = 1
        for idx, event in enumerate(events, start=1):
            if event.sequence != idx:
                return broken(idx, f"Sequence discontinuity: expected {idx}, found {event.sequence}")

            if event.prev_hash != expected_prev:
                return broken(
                    idx, f"Broken prev_hash at sequence {idx}: expected {expected_prev}, got {event.prev_hash}"
                )

            if event.hash_version < newest_version:
                return broken(
                    idx, f"Hash format downgrade at sequence {idx}: format {event.hash_version} after {newest_version}"
                )

            if not verify_event(event):
                return broken(idx, f"Tampered payload or signature at sequence {idx}")

            if self._key is not None and not self._signature_valid(event, self._key):
                return broken(idx, f"Missing or invalid signature at sequence {idx}")

            newest_version = event.hash_version
            legacy_events += event.hash_version == 1
            expected_prev = event.event_hash

        if anchor is not None:
            witnessed = events[anchor.sequence - 1] if anchor.sequence <= len(events) else None
            if witnessed is None or witnessed.event_hash != anchor.event_hash:
                return broken(anchor.sequence, f"Chain does not contain anchored event {anchor.sequence}")

        return ChainVerificationReport(
            valid=True,
            total_events=len(events),
            root_hash=root_hash,
            head_hash=head_hash,
            checked_at=now_ts,
            legacy_events=legacy_events,
            anchored=anchored,
        )
