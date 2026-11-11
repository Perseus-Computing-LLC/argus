"""severity: low
finding: with the native extension installed, verify_chain() raises OverflowError for an anchor sequence or a legacy-timestamp cutoff of 2**64 or more, where the pure-Python verifier returns a report.
Location: src/argus_ledger/ledger.py:432-437 (`_verify_chain_native` passes `anchor.sequence` and
`legacy_timestamps_before` straight to the extension), bindings/python/src/lib.rs:61 and :63 (the
`verify_lines` arguments are `u64`, so PyO3 raises OverflowError on conversion), against
src/argus_ledger/models.py:45
(`ChainAnchor.sequence` is `int` with `ge=1` and no upper bound) and the pure-Python loop in
src/argus_ledger/ledger.py:561-632, which handles both values.

Measured on this head, 5-record ledger:

  verify_chain(anchor=ChainAnchor(sequence=2**64, ...))   Python: valid=False, "Chain does not contain
                                                          anchored event ..."; native: OverflowError
  verify_chain(legacy_timestamps_before=2**64)            Python: valid=True; native: OverflowError

Effect: the two paths behind one call do not have the same contract for the same arguments; a caller
gets an uncaught OverflowError ("int too big to convert") instead of a verification report. An anchor is
data received from another party (models.py:42-44), so its sequence is not under the verifier's control.

Needs the argus_ledger_native extension; without it the differential tests are skipped, not passed.
"""
import pytest

from argus_ledger import AppendOnlyLedger, _native
from argus_ledger.models import ChainAnchor

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")


def _ledger(tmp_path):
    ledger = AppendOnlyLedger(str(tmp_path / "audit.jsonl"))
    events = [ledger.append("tool.call", "agent_1", {"n": n}) for n in range(1, 6)]
    return ledger, events


def _python(ledger, monkeypatch, **kwargs):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    report = ledger.verify_chain(**kwargs)
    assert report.verifier == "python"
    return report


def _native_report(ledger, monkeypatch, **kwargs):
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)
    report = ledger.verify_chain(**kwargs)  # must return a report, as the Python path does
    assert report.verifier == "native"
    return report


def test_control_python_path_reports_an_anchor_beyond_the_chain(tmp_path, monkeypatch):
    ledger, events = _ledger(tmp_path)
    anchor = ChainAnchor(sequence=2**64, event_hash=events[0].event_hash)
    report = _python(ledger, monkeypatch, anchor=anchor)
    assert not report.valid and report.first_broken_sequence == 2**64


@needs_native
def test_control_largest_u64_values_get_one_verdict(tmp_path, monkeypatch):
    ledger, events = _ledger(tmp_path)
    anchor = ChainAnchor(sequence=2**64 - 1, event_hash=events[0].event_hash)
    assert not _python(ledger, monkeypatch, anchor=anchor).valid
    assert not _native_report(ledger, monkeypatch, anchor=anchor).valid
    assert _python(ledger, monkeypatch, legacy_timestamps_before=2**64 - 1).valid
    assert _native_report(ledger, monkeypatch, legacy_timestamps_before=2**64 - 1).valid


@needs_native
def test_native_path_reports_an_anchor_sequence_of_2_to_the_64(tmp_path, monkeypatch):
    ledger, events = _ledger(tmp_path)
    anchor = ChainAnchor(sequence=2**64, event_hash=events[0].event_hash)
    python = _python(ledger, monkeypatch, anchor=anchor)
    native = _native_report(ledger, monkeypatch, anchor=anchor)
    assert (native.valid, native.first_broken_sequence) == (python.valid, python.first_broken_sequence)


@needs_native
def test_native_path_accepts_a_cutoff_of_2_to_the_64(tmp_path, monkeypatch):
    ledger, _ = _ledger(tmp_path)
    python = _python(ledger, monkeypatch, legacy_timestamps_before=2**64)
    native = _native_report(ledger, monkeypatch, legacy_timestamps_before=2**64)
    assert native.valid == python.valid
