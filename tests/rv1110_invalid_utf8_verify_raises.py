"""severity: low
finding: one byte that is not valid UTF-8 anywhere in the file makes verify_chain() and iter_events() raise UnicodeDecodeError instead of reporting the broken record, while head() and append() keep working on the same file.
Location: src/argus_ledger/ledger.py:118-146 (`_snapshot_lines` decodes with a strict
`io.TextIOWrapper(..., encoding="utf-8")`; the decode error is raised by `yield from text`, outside the
per-record `try` at ledger.py:404-411), reached from `verify_chain()` on both dispatch paths
(ledger.py:415-423 native, ledger.py:388-413 Python) and from `iter_events()` / `get_event()`.

A flipped top bit in any ASCII byte of a stored record (the ordinary single-bit storage fault) or a
payload string rewritten in Latin-1 produces such a byte. `verify_chain()` promises a report whose
`first_broken_sequence` is the chain position (ledger.py:484-493) and `_iter_records` promises
`LedgerCorruptionError` with a `position` for "a non-blank line that does not parse" (ledger.py:395-397).
Instead the caller gets `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9 in position N`, where N
is an offset inside a read buffer, not a record and not a file offset. A caller that handles
`LedgerCorruptionError` or tests `report.valid` does neither. Meanwhile `head()` returns the tail and
`append()` extends the chain, because the tail reader works on bytes (ledger.py:34-46): the writer keeps
adding records to a ledger that can no longer be verified.

The Rust side fails the same way (measured with `argus-verify` and `FileLedger` built from this head,
scratch rust_confirm.py): `FileLedger::verify_chain` returns `Err(LockError("read line 2 failed: stream
did not contain valid UTF-8"))` instead of a report, `argus-verify` exits 2 (its "usage error or file not
found" code, src/bin/argus_verify.rs:102-109) instead of 1 (integrity violation), and `FileLedger::head`
and `append` still succeed when the bad byte is not in the last record.
"""
import pytest

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError

CAFE_UTF8 = "caf\u00e9".encode("utf-8")
CAFE_LATIN1 = "caf\u00e9".encode("latin-1")  # 0xE9 followed by '"' is not valid UTF-8


def _ledger(tmp_path, damage_record=None, replacement=CAFE_LATIN1):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    for n in range(1, 4):
        ledger.append("tool.call", "agent_1", {"n": n, "note": "caf\u00e9"})
    if damage_record is not None:
        lines = path.read_bytes().split(b"\n")
        assert CAFE_UTF8 in lines[damage_record - 1]
        lines[damage_record - 1] = lines[damage_record - 1].replace(CAFE_UTF8, replacement)
        path.write_bytes(b"\n".join(lines))
    return ledger


@pytest.fixture(params=[True, False], ids=["pure_python", "default_dispatch"])
def dispatch(request, monkeypatch):
    if request.param:
        monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    else:
        monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)


def test_control_untouched_ledger_verifies(tmp_path, dispatch):
    report = _ledger(tmp_path).verify_chain()
    assert report.valid and report.total_events == 3


def test_control_valid_utf8_edit_is_reported_at_its_record(tmp_path, dispatch):
    report = _ledger(tmp_path, damage_record=2, replacement=b"cafe").verify_chain()
    assert not report.valid and report.first_broken_sequence == 2


@pytest.mark.parametrize("record", [1, 2, 3])
def test_verify_chain_reports_the_record_holding_the_bad_byte(tmp_path, dispatch, record):
    ledger = _ledger(tmp_path, damage_record=record)
    report = ledger.verify_chain()  # must return a report, not raise
    assert not report.valid
    assert report.first_broken_sequence == record


def test_iter_events_raises_ledger_corruption_error(tmp_path):
    ledger = _ledger(tmp_path, damage_record=2)
    with pytest.raises(LedgerCorruptionError):
        list(ledger.iter_events())


def test_append_does_not_extend_a_ledger_that_cannot_be_read(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    ledger = _ledger(tmp_path, damage_record=2)
    try:
        ledger.append("tool.call", "agent_1", {"n": 4})
    except LedgerCorruptionError:
        return  # refusing is consistent with the readers
    # If the writer accepts the file, the verifier must be able to give a verdict on it.
    report = ledger.verify_chain()
    assert report.first_broken_sequence == 2
