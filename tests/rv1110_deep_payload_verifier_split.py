"""severity: medium
finding: a ledger written by AppendOnlyLedger.append() with a payload nested 127 to 198 levels deep is valid for the pure-Python verifier and "malformed" for the native (Rust) verifier.
Location: src/argus_ledger/canonical.py:99-112 (`validate_payload` says it refuses what the Rust writer
refuses, and has no nesting limit) against src/lib.rs:216 (`AuditEvent::from_json_line`, serde_json with
its default recursion limit of 128) reached through src/argus_ledger/ledger.py:518-519.

The Python writer accepts the payload and the Python reader parses up to 200 levels, so
`verify_chain()` with ARGUS_LEDGER_PURE_PYTHON=1 reports valid. The same call with the
argus_ledger_native extension installed (the default dispatch) reports
"Malformed or partial event record at sequence N: ... recursion limit exceeded". Measured on this head
with `{"d": [[...1...]]}`: 126 nested lists agree (valid), 127 through 198 split, 199 and more are
covered by rv1110_deep_payload_bricks_ledger.py. Effect: whether an untampered ledger verifies depends
on whether an optional wheel is installed, and `argus-verify` (same parser) rejects ledgers the Python
package wrote and accepts.

Needs the argus_ledger_native extension; without it the differential tests are skipped, not passed.
"""
import pytest

from argus_ledger import AppendOnlyLedger, _native

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")


def _nested_lists(depth):
    value = 1
    for _ in range(depth):
        value = [value]
    return {"d": value}


def _verdicts(tmp_path, monkeypatch, depth):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    try:
        ledger.append("tool.result", "agent_1", _nested_lists(depth))
    except (TypeError, ValueError, RecursionError):
        return None  # refused by the writer: nothing to disagree about
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    python = ledger.verify_chain()
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON")
    native = ledger.verify_chain()
    assert python.verifier == "python" and native.verifier == "native"
    return python, native


@needs_native
def test_control_shallow_payload_both_verifiers_agree(tmp_path, monkeypatch):
    python, native = _verdicts(tmp_path, monkeypatch, 100)
    assert python.valid and native.valid
    assert python.head_hash == native.head_hash


@needs_native
@pytest.mark.parametrize("depth", [127, 150, 198])
def test_writer_accepted_payload_gets_one_verdict(tmp_path, monkeypatch, depth):
    verdicts = _verdicts(tmp_path, monkeypatch, depth)
    if verdicts is not None:
        python, native = verdicts
        assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
            f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
        )
