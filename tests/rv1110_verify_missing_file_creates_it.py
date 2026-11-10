"""severity: low
finding: verifying a ledger path that does not exist creates an empty 0600 file (and its directories) there and reports valid=True, so a deleted ledger is replaced by an "intact" empty one by the act of checking it.
Location: src/argus_ledger/ledger.py:195-199 (the constructor runs `os.makedirs` and
`os.open(..., O_CREAT)` for every caller, readers and verifiers included) and ledger.py:561-632
(`verify_chain()` on the file it just created returns `valid=True, total_events=0`). The Rust CLI treats
the same input as an I/O error: src/bin/argus_verify.rs:67 ("failed to read file") and :102-109 (exit 2).

ledger.py:487-488 documents that an empty chain passes without an anchor, so `valid=True` for an empty
file is the documented contract. What is not documented is that the read-only operation writes: a
monitor that runs `AppendOnlyLedger(path).verify_chain()` after the ledger was deleted, moved, or never
mounted gets "valid", and leaves behind an empty ledger file that the next writer extends from sequence
1. The evidence that the ledger was missing is gone, and the two verifiers disagree (Python: valid;
argus-verify built from this head: "file not found", exit 2, nothing created). `FileLedger::new` creates
the file as well and its `verify_chain` then reports valid with 0 events (scratch rust_confirm.py).

The tests assert that constructing a ledger object and verifying it does not create the file, and that
a missing ledger is not reported the same way as an intact one.
"""
import pytest

from argus_ledger import AppendOnlyLedger


@pytest.fixture(params=[True, False], ids=["pure_python", "default_dispatch"])
def dispatch(request, monkeypatch):
    if request.param:
        monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    else:
        monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)


def test_control_existing_empty_ledger_verifies_as_empty(tmp_path, dispatch):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    report = AppendOnlyLedger(str(path)).verify_chain()
    assert report.valid and report.total_events == 0


def test_control_writer_creates_the_file_on_append(tmp_path):
    path = tmp_path / "state" / "audit.jsonl"
    AppendOnlyLedger(str(path)).append("tool.call", "agent_1", {"n": 1})
    assert path.exists()


def test_verifying_a_missing_ledger_does_not_create_it(tmp_path, dispatch):
    path = tmp_path / "not-mounted" / "audit.jsonl"
    try:
        AppendOnlyLedger(str(path)).verify_chain()
    except OSError:
        pass  # refusing to verify a file that is not there is correct
    assert not path.exists(), "a verification call created the ledger file it was asked to check"
    assert not path.parent.exists(), "a verification call created the ledger directory"


def test_missing_ledger_is_not_reported_as_valid(tmp_path, dispatch):
    path = tmp_path / "audit.jsonl"
    writer = AppendOnlyLedger(str(path))
    writer.append("tool.call", "agent_1", {"n": 1})
    path.unlink()  # the ledger is deleted behind the verifier's back
    try:
        report = AppendOnlyLedger(str(path)).verify_chain()
    except OSError:
        return
    assert not report.valid, "a ledger file that does not exist verified as valid"
