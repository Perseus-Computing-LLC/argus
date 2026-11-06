"""Append-only audit ledger implementation with file locking and hash chaining."""

from __future__ import annotations

import calendar
import contextlib
import datetime
import errno
import fcntl
import io
import os
import stat
import uuid
import warnings
from typing import Any, Dict, Iterator, Optional, Union
from . import _native
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


# Group and other permission bits: a ledger file holds audit payloads and is kept owner-only.
_GROUP_OTHER_BITS = 0o077
# A writer that keeps finding a different file at the path after taking the lock gives up after this.
_REOPEN_ATTEMPTS = 16


def _restrict_to_owner(fd: int, path: str) -> None:
    """Remove group/other permission bits from the file open at ``fd`` before anything is written to it.

    The constructor creates the file 0600, but the file at the path can be replaced while a writer runs
    (log rotation that creates a fresh file, an operator's ``touch`` under umask 022, another tool).
    Raises ``PermissionError`` rather than write a payload into a file that group or others can read."""
    mode = stat.S_IMODE(os.fstat(fd).st_mode)
    if mode & _GROUP_OTHER_BITS:
        try:
            os.fchmod(fd, mode & ~_GROUP_OTHER_BITS)
        except OSError as exc:
            raise PermissionError(
                f"Ledger file {path} is accessible to group or others (mode {mode:o}) and cannot be made "
                f"owner-only: {exc}; refusing to append"
            ) from exc


class _PrefixReader(io.RawIOBase):
    """The first ``size`` bytes of the file open at ``fd``, read with ``pread``.

    The file is append-only, so those bytes never change once a snapshot has taken ``size`` under the
    shared lock, and bytes appended later are never returned."""

    def __init__(self, fd: int, size: int) -> None:
        super().__init__()
        self._fd = fd
        self._size = size
        self._pos = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        want = min(len(buffer), self._size - self._pos)
        if want <= 0:
            return 0
        chunk = os.pread(self._fd, want, self._pos)
        buffer[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)


def _snapshot_lines(path: str) -> Iterator[str]:
    """Yield the lines of the file at ``path`` as it stood at one instant, holding no lock between yields.

    The shared lock is held only while the file size is read. Writers hold LOCK_EX for a whole append,
    so that size ends where the last complete append ended, and appends only add bytes after it. The
    prefix is then read without a lock: a caller that appends while iterating, or never finishes, cannot
    block (or self-deadlock) a writer. Lines are decoded exactly as ``open(path, encoding="utf-8")``
    decodes them."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return
    text: Optional[io.TextIOWrapper] = None
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            size = os.fstat(fd).st_size
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
        text = io.TextIOWrapper(
            io.BufferedReader(_PrefixReader(fd, size), buffer_size=_TAIL_BLOCK), encoding="utf-8"
        )
        yield from text
    finally:
        if text is not None:
            text.close()  # closes the wrappers only; the descriptor is closed below
        os.close(fd)


def _parse_record(record: Union[str, bytes]) -> AuditEvent:
    """Parse one stored record: the one parse shared by ``head()``, the readers and the writer's tail
    gate, so the writer never extends a record its own reader rejects. Any failure propagates."""
    return AuditEvent.model_validate_json(record)


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

        ``require_signature=True`` refuses to open without a key. The ledger file is created owner-only (0600),
        on every append as well as here, and an existing file that group or others can access is made
        owner-only when the ledger is opened (best effort) and before each append (or the append is refused)."""
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
        else:
            # Like the Rust FileLedger::open (which resets the mode to 0600, best effort), records already
            # in the file are kept owner-only: group/other bits are cleared, owner bits are left alone.
            # Best effort here (a verifier may open a file it does not own); append() insists.
            try:
                mode = stat.S_IMODE(os.stat(self.ledger_path).st_mode)
                if mode & _GROUP_OTHER_BITS:
                    os.chmod(self.ledger_path, mode & ~_GROUP_OTHER_BITS)
            except OSError:
                pass

    @staticmethod
    def load_key(path: str) -> bytes:
        """Read a signing key from a file that only its owner can access."""
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"Key file {path} is readable by group or others (mode {mode:o}); chmod 600 it.")
        with open(path, "rb") as fh:
            return fh.read().strip()

    def _open_locked_for_append(self) -> int:
        """Return a descriptor for the file now at ``ledger_path``, opened for appending and held under LOCK_EX.

        A missing file is created owner-only (0600) whatever the umask: a writer that outlives the file it
        was constructed for (rotated away, moved aside, deleted) must not recreate it readable by group or
        others. The lock is a lock on one file, not on the path, so after it is granted the descriptor is
        checked to still be the file at the path; a writer that waited across a rotation would otherwise
        append to the rotated file. Group/other bits on the file are then removed, or the append refused."""
        for _ in range(_REOPEN_ATTEMPTS):
            fd = os.open(self.ledger_path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                held = os.fstat(fd)
                try:
                    current = os.stat(self.ledger_path)
                except FileNotFoundError:
                    current = None
                if current is not None and (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
                    _restrict_to_owner(fd, self.ledger_path)
                    return fd
            except BaseException:
                os.close(fd)
                raise
            os.close(fd)  # releases the lock on the file that is no longer at the path; reopen
        raise OSError(
            errno.EAGAIN,
            f"Ledger file {self.ledger_path} was replaced {_REOPEN_ATTEMPTS} times while waiting for its lock",
        )

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

        fd = self._open_locked_for_append()
        try:
            size = os.fstat(fd).st_size
            tail = _tail_record(fd)

            last_instant: Optional[int] = None
            if tail is None:
                sequence = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                # The tail must be a record head() accepts, and its timestamp must parse: the
                # strictly-increasing floor below is taken from it, and verify_chain() rejects a
                # malformed timestamp. Extending (and signing onto) a tail the reader or the
                # verifier rejects would chain new records to a head nobody can confirm.
                try:
                    last = _parse_record(tail)
                except Exception as exc:
                    raise LedgerCorruptionError(
                        "Cannot append to ledger with corrupted tail record at line "
                        f"{_count_records(self.ledger_path)}: {exc}"
                    ) from exc
                last_instant = timestamp_nanos(last.timestamp)
                if last_instant is None:
                    raise LedgerCorruptionError(
                        "Cannot append to ledger with corrupted tail record at line "
                        f"{_count_records(self.ledger_path)}: malformed timestamp {last.timestamp!r}"
                    )
                sequence = last.sequence + 1
                prev_hash = last.event_hash

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
            separator = "" if size == 0 or os.pread(fd, 1, size - 1) == b"\n" else "\n"
            data = memoryview((separator + event.model_dump_json() + "\n").encode("utf-8"))
            while data:  # O_APPEND: every write lands at the end of the file
                data = data[os.write(fd, data):]
            os.fsync(fd)
            return event
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

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
                    return _parse_record(record)
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
        """Yield every record in file order, one at a time, from a snapshot of the file.

        The shared lock is held only while the snapshot is taken (see ``_snapshot_lines``), never
        between yields: a suspended iterator does not block writers, and ``append()`` inside the
        loop does not deadlock. Records appended after the snapshot are not yielded.

        A non-blank line that does not parse raises ``LedgerCorruptionError`` whose
        ``position`` is the count of non-blank lines up to and including it: the chain
        position the record should occupy, never a value read from the record."""
        with contextlib.closing(_snapshot_lines(self.ledger_path)) as lines:
            position = 0
            for line_no, line in enumerate(lines, start=1):
                line = line.strip()
                if not line:
                    continue
                position += 1
                try:
                    event = _parse_record(line)
                except Exception as exc:
                    err = LedgerCorruptionError(
                        f"Malformed event record at line {line_no}: {exc}"
                    )
                    err.position = position  # type: ignore[attr-defined]
                    raise err from exc
                yield event

    def _iter_lines(self) -> Iterator[str]:
        """Yield every non-blank line in file order from a snapshot of the file, without parsing it;
        no lock is held between yields. The native verifier parses fail-closed, so a torn line fails
        at its chain position."""
        with contextlib.closing(_snapshot_lines(self.ledger_path)) as lines:
            for line in lines:
                line = line.strip()
                if line:
                    yield line

    def _verify_chain_native(
        self,
        anchor: Optional[ChainAnchor],
        legacy_timestamps_before: Optional[int],
        now_ts: str,
    ) -> ChainVerificationReport:
        """verify_chain through the Rust ChainVerifier; same report shape and warning contract."""
        out = _native.verify_lines(
            self._iter_lines(),
            anchor=(anchor.sequence, anchor.event_hash) if anchor is not None else None,
            verifying_key=self._ed25519_public_key,
            legacy_timestamps_before=legacy_timestamps_before,
        )
        detail = out["error_detail"]
        if out["failure_kind"] == "parse":
            # Same wording as the Python loop's LedgerCorruptionError path.
            detail = f"Malformed or partial event record at sequence {out['first_broken_sequence']}: {detail}"
        for text in out["warnings"]:
            warnings.warn(text, UserWarning, stacklevel=3)
        return ChainVerificationReport(
            valid=out["valid"],
            total_events=out["total_events"],
            root_hash=out["root_hash"],
            head_hash=out["head_hash"],
            first_broken_sequence=out["first_broken_sequence"],
            error_detail=detail,
            checked_at=now_ts,
            legacy_events=out["legacy_events"],
            legacy_timestamp_regressions=out["legacy_timestamp_regressions"],
            warnings=list(out["warnings"]),
            anchored=anchor is not None,
            verifier="native",
        )

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

        # One verifier in two languages (issue #15): with the argus_ledger_native extension
        # present, the Rust ChainVerifier produces the verdict. HMAC-signed ledgers stay here
        # because the Rust crate has no HMAC scheme; ARGUS_LEDGER_PURE_PYTHON=1 opts out.
        hmac_signed = self._key is not None and not self._use_ed25519
        if _native.enabled() and not hmac_signed:
            return self._verify_chain_native(anchor, legacy_timestamps_before, now_ts)

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
