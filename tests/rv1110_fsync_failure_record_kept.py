"""severity: low
finding: when os.fsync fails after the record was written, append() raises but the record stays in the file as a normal chained (and signed) event; the caller is told the event was not logged and a retry records it twice.
Location: src/argus_ledger/ledger.py:333-341 (write loop, then `os.fsync(fd)` at :337; on an exception
the `finally` only unlocks and closes, the complete line already written is left in place). The Rust
writer has the same order (src/file_ledger.rs:334-338: `write_all` then `sync_data`, error returned with
the line left in the file); that side is by reading only.

Measured on this head: with fsync raising EIO, `append("payment.sent", ...)` raises OSError, yet the
file gains the record, `head()` returns it, the next `append()` chains onto it as sequence 3 and
`verify_chain()` reports 3 valid events. So an append that reported failure is a permanent, verifiable
ledger entry. A caller that follows the exception (does not perform the audited action, or retries the
append) ends with a ledger that records an action that was not taken, or the same action twice under
two event ids. The record is also the one whose durability the failed fsync could not confirm.

This is the complete-write counterpart of rv1110_failed_append_leaves_torn_tail.py (partial write).
The test accepts either consistent outcome for a failed append: the record is absent afterwards, or
the call did not raise.
"""
import errno
import os

import pytest

from argus_ledger import AppendOnlyLedger


def _ledger(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    return path, ledger


def _failing_fsync(fd):
    raise OSError(errno.EIO, os.strerror(errno.EIO))


def test_control_append_calls_fsync_and_succeeds(tmp_path, monkeypatch):
    path, ledger = _ledger(tmp_path)
    calls = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real_fsync(fd))[1])
    assert ledger.append("payment.sent", "agent_1", {"amount": 2}).sequence == 2
    assert calls, "append() did not call os.fsync, so the fault below would not be injected"


def test_control_fsync_failure_reaches_the_caller(tmp_path, monkeypatch):
    path, ledger = _ledger(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", _failing_fsync)
        with pytest.raises(OSError):
            ledger.append("payment.sent", "agent_1", {"amount": 2})


def test_append_that_raised_did_not_record_the_event(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path, ledger = _ledger(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", _failing_fsync)
        with pytest.raises(OSError):
            ledger.append("payment.sent", "agent_1", {"amount": 2})

    recorded = [event.event_type for event in ledger.iter_events()]
    assert recorded == ["tool.call"], f"the append raised, but the ledger now holds {recorded}"


def test_retry_after_a_failed_append_records_the_event_once(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path, ledger = _ledger(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", _failing_fsync)
        with pytest.raises(OSError):
            ledger.append("payment.sent", "agent_1", {"amount": 2})

    ledger.append("payment.sent", "agent_1", {"amount": 2})  # the caller retries

    payments = [event for event in ledger.iter_events() if event.event_type == "payment.sent"]
    assert len(payments) == 1, f"one payment was audited {len(payments)} times"
