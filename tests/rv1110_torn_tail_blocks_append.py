"""severity: medium
finding: a writer killed part-way through an append leaves a fragment that every later append() refuses; nothing in the package recovers from it, so one crash stops the audit trail until the file is edited by hand.
Location: src/argus_ledger/ledger.py:277-283 (tail gate: any unparsable last line raises
`LedgerCorruptionError("Cannot append to ledger with corrupted tail record ...")`) together with
ledger.py:333-337 (the record is written with plain `os.write` calls and fsynced afterwards, so a crash
or power loss can leave any prefix of it on disk). The Rust writer has the same pair
(src/file_ledger.rs:253-254 and 334-338); confirmed after the fact with `FileLedger` built from this head
(scratch rust_confirm.py: `head()` and `append()` both return Err on the same file).

`append()` returns only after `os.fsync` (ledger.py:337), and every record it completes ends in "\\n"
(ledger.py:334). A last line that has no newline and does not parse was therefore never acknowledged to
any caller: it is the remains of an append that did not happen. The writer treats it like tampering
instead: `head()` raises, `append()` raises on every call, `verify_chain()` reports the file broken at
that position, and the package has no repair or recovery call (no function in src/argus_ledger truncates
or quarantines a tail). An agent whose process is OOM-killed between two `os.write` calls cannot log
again after restart.

docs/SECURITY_ASSESSMENT_SCOPE.md:53 lists "F1 (Self-bricking writer)" as "Resolved ... by atomic
transaction flush and lock recovery". README.md:20 promises "sync_data durability"; the durable records
are intact here, the ledger is just no longer writable.

The tests accept any recovery that keeps the acknowledged records: after the crash the next append must
succeed, the records acknowledged before the crash must still be the first records of the chain, and
the chain must verify. If refusing is the intended policy, the finding is that no supported way out
exists and the state is not documented.
"""
import pytest

from argus_ledger import AppendOnlyLedger


def _ledger_after_crash(tmp_path, surviving_bytes):
    """Two acknowledged records, then the first `surviving_bytes` bytes of a third (no newline)."""
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    first = ledger.append("tool.call", "agent_1", {"n": 1})
    second = ledger.append("tool.call", "agent_1", {"n": 2})
    acknowledged = path.read_bytes()
    ledger.append("tool.call", "agent_1", {"n": 3})
    third = path.read_bytes()[len(acknowledged):]
    assert 0 < surviving_bytes < len(third) - 1
    path.write_bytes(acknowledged + third[:surviving_bytes])
    return path, [first.event_hash, second.event_hash]


def test_control_fragment_is_detected_by_verify_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path, _ = _ledger_after_crash(tmp_path, 60)
    report = AppendOnlyLedger(str(path)).verify_chain()
    assert not report.valid and report.first_broken_sequence == 3


def test_control_complete_record_without_newline_is_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    ledger.append("tool.call", "agent_1", {"n": 2})
    path.write_bytes(path.read_bytes()[:-1])  # the crash took only the final newline
    assert AppendOnlyLedger(str(path)).append("tool.call", "agent_1", {"n": 3}).sequence == 3
    assert ledger.verify_chain().valid


@pytest.mark.parametrize("surviving_bytes", [1, 60, 200])
def test_writer_recovers_after_a_crash_mid_append(tmp_path, monkeypatch, surviving_bytes):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path, acknowledged_hashes = _ledger_after_crash(tmp_path, surviving_bytes)
    restarted = AppendOnlyLedger(str(path))  # the process comes back up

    restarted.append("agent.restart", "agent_1", {"n": 3})

    report = restarted.verify_chain()
    assert report.valid, report.error_detail
    hashes = [event.event_hash for event in restarted.iter_events()]
    assert hashes[:2] == acknowledged_hashes, "an acknowledged record was lost in recovery"
