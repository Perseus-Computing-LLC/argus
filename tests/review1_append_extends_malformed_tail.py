"""severity: low
finding: AppendOnlyLedger.append() chains and signs a new record onto a tail record that head() and verify_chain() reject as malformed; the corrupted-tail gate only checks that "sequence" and "event_hash" are readable.
append() reads the tail with json.loads and takes int(last["sequence"]) and str(last["event_hash"])
(src/argus_ledger/ledger.py:147-156); a tail without "timestamp" (or any other required field) passes,
and timestamp_nanos("") silently drops the monotonic floor (ledger.py:151, 162). head() parses the same
line as an AuditEvent and raises LedgerCorruptionError (ledger.py:217-222), and the Rust writer parses the
tail with AuditEvent::from_json_line and refuses (src/file_ledger.rs:388-391). The writer's own refusal,
"Cannot append to ledger with corrupted tail record", is therefore skipped: a signing writer extends and
signs a chain whose head is already broken and returns an event whose anchor() commits to it.
"""
import json

import pytest

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError

KEY = b"argus-review-hmac-key-0123456789"


def _ledger_with_damaged_tail(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path), signing_key=KEY)
    ledger.append("tool.call", "agent_1", {"n": 1})
    ledger.append("tool.call", "agent_1", {"n": 2})
    lines = path.read_text(encoding="utf-8").splitlines()
    tail = json.loads(lines[-1])
    del tail["timestamp"]
    lines[-1] = json.dumps(tail, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path, ledger


def test_control_reader_and_verifier_reject_the_tail(tmp_path):
    _path, ledger = _ledger_with_damaged_tail(tmp_path)
    with pytest.raises(LedgerCorruptionError):
        ledger.head()
    report = ledger.verify_chain()
    assert report.valid is False
    assert report.first_broken_sequence == 2


def test_append_refuses_a_tail_that_head_rejects(tmp_path):
    path, ledger = _ledger_with_damaged_tail(tmp_path)
    before = path.read_bytes()
    with pytest.raises(LedgerCorruptionError):
        ledger.append("tool.call", "agent_1", {"n": 3})
    assert path.read_bytes() == before, "append wrote a record after a malformed tail"
