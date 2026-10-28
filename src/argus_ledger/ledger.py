"""Append-only audit ledger implementation with file locking and hash chaining."""

from __future__ import annotations

import calendar
import datetime
import fcntl
import json
import os
import uuid
import warnings
from typing import Any, Dict, Iterator, Optional
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
from .canonical import validate_identifiers, validate_payload
from .timestamps import timestamp_nanos

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


def _monotonic_utc_iso(last_instant: Optional[int]) -> str:
    """Current UTC time as RFC 3339, forced at least one microsecond past ``last_instant`` (ns)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if last_instant is not None:
        now_ns = (calendar.timegm(now.timetuple()) * 1_000_000 + now.microsecond) * 1000
        floor_ns = last_instant + 1
        if now_ns < floor_ns:
            # Round up to the next whole microsecond so the emitted (microsecond) text is still
            # strictly after a nanosecond-resolution Rust record.
            floor_us = -(-floor_ns // 1000)
            now = datetime.datetime.fromtimestamp(floor_us / 1_000_000, datetime.timezone.utc)
            now = now.replace(microsecond=floor_us % 1_000_000)
    return now.isoformat()


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
        verify_key: Optional[bytes] = None,
    ) -> None:
        """``signing_key``: when set, every event is signed, with HMAC-SHA256 under this secret or, with
        ``use_ed25519=True``, with Ed25519 under this 32-byte private seed; verification then fails for an
        event whose signature is missing, wrong or in the other scheme. Rewriting the whole chain then needs
        the key, not just the file.

        ``verify_key``: a 32-byte Ed25519 public key, to check an Ed25519-signed ledger without its private
        key. Such a ledger checks Ed25519 signatures only and cannot append. Never pass a public key as
        ``signing_key``: that is an HMAC secret, and anyone who knows the public key could sign with it.

        ``require_signature=True`` refuses to open without a key. The ledger file is created owner-only (0600)."""
        if signing_key is not None and verify_key is not None:
            raise ValueError("pass signing_key (to sign) or verify_key (to check Ed25519 signatures), not both")
        if require_signature and not (signing_key or verify_key):
            raise ValueError("require_signature=True needs a signing_key or a verify_key")
        if signing_key is not None and len(signing_key) < 16:
            raise ValueError("signing_key must be at least 16 bytes")
        if use_ed25519:
            if signing_key is None or len(signing_key) != 32:
                raise ValueError("use_ed25519=True requires a 32-byte Ed25519 seed/private key")
        if verify_key is not None and len(verify_key) != 32:
            raise ValueError("verify_key must be a 32-byte Ed25519 public key")
        self._key = signing_key
        self._use_ed25519 = use_ed25519
        self._signed = signing_key is not None or verify_key is not None
        # Derived once: verification then needs one signature check per event, not a key derivation.
        self._ed25519_public_key = (
            ed25519_public_key(signing_key) if use_ed25519 and signing_key is not None else verify_key
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
        if self._key is None and self._ed25519_public_key is not None:
            raise PermissionError("this ledger was opened with verify_key: it can check signatures but not append")
        # Same gates as the Rust writer, before anything is locked or written.
        validate_identifiers(event_type, actor)
        validate_payload(payload)

        with open(self.ledger_path, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                size = os.fstat(f.fileno()).st_size
                tail = _tail_record(f.fileno())

                last_instant: Optional[int] = None
                if tail is None:
                    sequence = 1
                    prev_hash = GENESIS_PREV_HASH
                else:
                    try:
                        last_obj = json.loads(tail)
                        sequence = int(last_obj["sequence"]) + 1
                        prev_hash = str(last_obj["event_hash"])
                        last_instant = timestamp_nanos(last_obj.get("timestamp", ""))
                    except (ValueError, KeyError, TypeError) as exc:
                        raise LedgerCorruptionError(
                            "Cannot append to ledger with corrupted tail record at line "
                            f"{_count_records(self.ledger_path)}: {exc}"
                        ) from exc

                # Strictly increasing within the ledger even if the host clock steps backwards
                # (seen in production: 47 decreasing transitions in 34k records). The guard is
                # taken under the lock so two writers cannot pick the same instant. Format is
                # unchanged: RFC 3339 UTC, explicit +00:00, microsecond resolution.
                now_ts = _monotonic_utc_iso(last_instant)

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

    @property
    def head_hash(self) -> Optional[str]:
        """Event hash of the latest ledger record, or None if the ledger is empty."""
        latest = self.head()
        return latest.event_hash if latest else None

    @property
    def last_hash(self) -> Optional[str]:
        """Alias for head_hash."""
        return self.head_hash

    @property
    def current_sequence(self) -> int:
        """Sequence index of the latest ledger record, or 0 if empty."""
        latest = self.head()
        return latest.sequence if latest else 0

    def __len__(self) -> int:
        return self.current_sequence

    def get_event(self, sequence: int) -> Optional[AuditEvent]:
        for event in self.iter_events():
            if event.sequence == sequence:
                return event
        return None

    def _iter_records(self) -> Iterator[AuditEvent]:
        """Yield every record in file order, one at a time, under a shared lock.

        A non-blank line that does not parse raises ``LedgerCorruptionError`` whose
        ``position`` is the count of non-blank lines up to and including it: the chain
        position the record should occupy, never a value read from the record."""
        if not os.path.exists(self.ledger_path):
            return
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                position = 0
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    position += 1
                    try:
                        yield AuditEvent.model_validate_json(line)
                    except Exception as exc:
                        err = LedgerCorruptionError(
                            f"Malformed event record at line {line_no}: {exc}"
                        )
                        err.position = position  # type: ignore[attr-defined]
                        raise err from exc
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def iter_events(self, start: int = 1, end: Optional[int] = None) -> Iterator[AuditEvent]:
        for event in self._iter_records():
            if event.sequence < start:
                continue
            if end is not None and event.sequence > end:
                break
            yield event

    def _signature_valid(self, event: AuditEvent) -> bool:
        if self._ed25519_public_key is not None:
            return verify_signature_ed25519(event, self._ed25519_public_key)
        assert self._key is not None
        return verify_signature(event, self._key, scheme="hmac")

    def _signature_error(self, event: AuditEvent, position: int) -> str:
        if self._ed25519_public_key is None and (event.signature or "").startswith("ed25519:"):
            return (f"Ed25519 signature at sequence {position}, but this ledger checks HMAC signatures; "
                    "open it with verify_key=<Ed25519 public key> to check Ed25519 signatures")
        return f"Missing or invalid signature at sequence {position}"

    def verify_chain(
        self,
        anchor: Optional[ChainAnchor] = None,
        legacy_timestamps_before: Optional[int] = None,
    ) -> ChainVerificationReport:
        """Verify sequence numbers, hash links, event hashes, timestamp order and, with a key,
        signatures, in one pass over the file with one record resident at a time.

        Without ``anchor`` this proves internal consistency only: an empty, truncated or fully
        recomputed chain passes, and only a key stops someone who can write the file from
        recomputing it. ``anchor`` (``AuditEvent.anchor()`` kept where the writer cannot change it)
        also detects rollback, truncation below the anchor and rewritten history up to it.
        ``first_broken_sequence`` is the chain position, never a value read from the record.
        On failure ``total_events`` is the number of records read up to and including the
        broken one; the rest of the file is not read.

        ``legacy_timestamps_before`` is the accept-as-historic cutoff (issue #14). Ledgers written
        before the strictly-increasing timestamp rule can hold records whose timestamp is not after
        their predecessor's (a host clock stepping backwards). With this set to a sequence ``>= 1``,
        such a regression at a sequence below the cutoff is counted in
        ``report.legacy_timestamp_regressions`` and reported once as a ``UserWarning`` and in
        ``report.warnings`` instead of failing the chain. Hashes, ``prev_hash`` links, sequence
        continuity, malformed timestamps and malformed lines stay strict everywhere, and the strict
        timestamp rule applies from the cutoff onwards. The Rust library and ``argus-verify
        --legacy-timestamps-before`` apply the same rule."""
        if legacy_timestamps_before is not None:
            # Sequence numbers start at 1, so 0 (or a bool, which int accepts) is a caller mistake;
            # refuse it rather than silently behaving as if the option were unset.
            if isinstance(legacy_timestamps_before, bool) or not isinstance(legacy_timestamps_before, int):
                raise TypeError("legacy_timestamps_before must be an int >= 1 or None")
            if legacy_timestamps_before < 1:
                raise ValueError("legacy_timestamps_before must be >= 1")
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        anchored = anchor is not None

        # Running state: a 50k-record ledger must not cost 50k resident models (F3).
        position = 0
        root_hash = ""
        head_hash = ""
        legacy_events = 0
        legacy_timestamp_regressions = 0
        first_legacy_regression: Optional[int] = None
        expected_prev = GENESIS_PREV_HASH
        prev_instant: Optional[int] = None
        anchor_matched = False

        def warning_lines(stacklevel: int) -> list:
            # One warning for the whole pass, not one per record: a historic ledger can hold
            # dozens, and the count plus the first position is what decides whether the cutoff
            # is right. Emitted when the report is built so it also fires on a later failure;
            # ``stacklevel`` points the warning at verify_chain's caller from either path.
            if first_legacy_regression is None:
                return []
            text = (
                f"{legacy_timestamp_regressions} timestamp regression(s) accepted as historic below "
                f"sequence {legacy_timestamps_before} (first at sequence {first_legacy_regression})"
            )
            warnings.warn(text, UserWarning, stacklevel=stacklevel)
            return [text]

        def broken(at: int, detail: str) -> ChainVerificationReport:
            return ChainVerificationReport(
                valid=False,
                total_events=position,
                root_hash=root_hash,
                head_hash=head_hash,
                first_broken_sequence=at,
                error_detail=detail,
                checked_at=now_ts,
                legacy_events=legacy_events,
                legacy_timestamp_regressions=legacy_timestamp_regressions,
                warnings=warning_lines(stacklevel=4),
                anchored=anchored,
            )

        records = self._iter_records()
        while True:
            try:
                event = next(records)
            except StopIteration:
                break
            except LedgerCorruptionError as exc:
                position = getattr(exc, "position", position + 1)
                return broken(position, f"Malformed or partial event record at sequence {position}: {exc}")
            position += 1
            idx = position

            if event.sequence != idx:
                return broken(idx, f"Sequence discontinuity: expected {idx}, found {event.sequence}")

            if event.prev_hash != expected_prev:
                return broken(
                    idx, f"Broken prev_hash at sequence {idx}: expected {expected_prev}, got {event.prev_hash}"
                )

            # Format-1 records may follow format-2 ones while a process still runs the previous release.
            # Relabelling a record's format cannot make it verify: its stored hash commits to one format.
            if not verify_event(event):
                return broken(idx, f"Tampered payload or signature at sequence {idx}")

            # Timestamp contract (shared with the Rust crate and argus-verify): strictly
            # increasing as instants, so a replayed or back-dated record cannot be spliced in.
            # A timestamp that does not parse always fails. One that is not strictly after its
            # predecessor fails unless the record lies below the accept-as-historic cutoff
            # (issue #14), in which case it is counted and reported once.
            instant = timestamp_nanos(event.timestamp)
            if instant is None:
                return broken(idx, f"Timestamp at sequence {idx} is malformed or not increasing")
            if prev_instant is not None and instant <= prev_instant:
                historic = legacy_timestamps_before is not None and idx < legacy_timestamps_before
                if not historic:
                    return broken(idx, f"Timestamp at sequence {idx} is malformed or not increasing")
                legacy_timestamp_regressions += 1
                if first_legacy_regression is None:
                    first_legacy_regression = idx

            if self._signed and not self._signature_valid(event):
                return broken(idx, self._signature_error(event, idx))

            if anchor is not None and anchor.sequence == idx:
                if event.event_hash != anchor.event_hash:
                    return broken(idx, f"Chain does not contain anchored event {idx}")
                anchor_matched = True

            legacy_events += event.hash_version == 1
            expected_prev = event.event_hash
            prev_instant = instant
            if idx == 1:
                root_hash = event.event_hash
            head_hash = event.event_hash

        if anchor is not None and not anchor_matched:
            # The anchor lies beyond the head: the file was truncated or rolled back.
            return broken(anchor.sequence, f"Chain does not contain anchored event {anchor.sequence}")

        return ChainVerificationReport(
            valid=True,
            total_events=position,
            root_hash=root_hash,
            head_hash=head_hash,
            checked_at=now_ts,
            legacy_events=legacy_events,
            legacy_timestamp_regressions=legacy_timestamp_regressions,
            warnings=warning_lines(stacklevel=3),
            anchored=anchored,
        )
