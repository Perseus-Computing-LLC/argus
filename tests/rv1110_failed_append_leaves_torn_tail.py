"""severity: medium
finding: an append() whose write fails part-way (disk full after a short write) leaves the partial record in the file, and every later append() then raises LedgerCorruptionError.
Location: src/argus_ledger/ledger.py:333-338. The record is written in a loop of `os.write` calls
(ledger.py:335-336) while the writer holds LOCK_EX and already knows the pre-append size (ledger.py:265),
but on an exception the `finally` at ledger.py:339-341 only unlocks and closes: the bytes already written
are not removed. The tail gate at ledger.py:277-283 then refuses the fragment for ever.

Effect: one transient ENOSPC/EDQUOT/EIO during an append turns into a permanent outage of the audit
trail. The append raises (correct), the file keeps e.g. `{"sequence":2,"event_id":"4c9b...` with no
newline, `head()` raises, `verify_chain()` reports the ledger broken at that position, and after space is
freed no append succeeds until someone edits the file by hand; the package has no repair call. The same
on-disk state is what a writer killed between two `os.write` calls leaves behind.
The Rust writer has the same shape (src/file_ledger.rs:334-338 and 458-462: `write_all` then
`sync_data`, no `set_len` back on error); that side is by reading only.

docs/SECURITY_ASSESSMENT_SCOPE.md:53 says the self-bricking writer was "Resolved in PR #13 by atomic
transaction flush and lock recovery"; the append is not atomic.

The fault is injected by replacing `os.write` (the function the ledger module calls) for the duration of
one append: the first call writes 40 bytes of the record, the second raises ENOSPC.
"""
import errno
import os

import pytest

import argus_ledger.ledger as ledger_module
from argus_ledger import AppendOnlyLedger


def _ledger(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    return path, ledger


def _append_with_disk_full(monkeypatch, ledger, short_write_bytes):
    """Run one append during which the disk fills up after `short_write_bytes` bytes."""
    real_write = os.write
    calls = []

    def flaky_write(fd, data):
        calls.append(len(data))
        if len(calls) == 1 and short_write_bytes:
            return real_write(fd, bytes(data[:short_write_bytes]))
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(ledger_module.os, "write", flaky_write)
        with pytest.raises(OSError) as raised:
            ledger.append("tool.call", "agent_1", {"n": 2})
    assert raised.value.errno == errno.ENOSPC
    assert calls, "the injected os.write was not reached"


def test_control_write_that_fails_before_any_byte_changes_nothing(tmp_path, monkeypatch):
    path, ledger = _ledger(tmp_path)
    before = path.read_bytes()
    _append_with_disk_full(monkeypatch, ledger, short_write_bytes=0)
    assert path.read_bytes() == before
    assert ledger.append("tool.call", "agent_1", {"n": 2}).sequence == 2
    assert ledger.verify_chain().valid


def test_failed_append_leaves_the_file_as_it_was(tmp_path, monkeypatch):
    path, ledger = _ledger(tmp_path)
    before = path.read_bytes()
    _append_with_disk_full(monkeypatch, ledger, short_write_bytes=40)
    assert path.read_bytes() == before, "the failed append left a partial record behind"


def test_ledger_accepts_appends_again_once_the_disk_has_room(tmp_path, monkeypatch):
    path, ledger = _ledger(tmp_path)
    _append_with_disk_full(monkeypatch, ledger, short_write_bytes=40)
    event = ledger.append("tool.call", "agent_1", {"n": 2})
    assert event.sequence == 2
    report = ledger.verify_chain()
    assert report.valid, report.error_detail
