"""severity: high
finding: one append() of a payload nested about 200 levels deep succeeds and leaves a tail that head(), verify_chain() and every later append() reject: the writer bricks its own ledger.
Location: src/argus_ledger/canonical.py:99-112 (`validate_payload` has no nesting limit),
src/argus_ledger/ledger.py:334-338 (the record is written and fsynced without being read back) and
ledger.py:277-283 (the tail gate then refuses the record this same writer produced).

`json.dumps` and pydantic's serializer both handle a few hundred levels, so the gate at ledger.py:260-261
passes and the line is written. The reader (`AuditEvent.model_validate_json`, ledger.py:150) stops at its
JSON recursion limit (200 levels including the record object and the payload object), so the stored line
is "malformed" to `head()`, `iter_events()`, `verify_chain()` and to the next `append()`, which raises
`LedgerCorruptionError("Cannot append to ledger with corrupted tail record ...")` on every call from then
on. The payload is under 1 KiB. Measured on this head with `{"d": [[...1...]]}`: 198 nested lists are
readable, 199 and more are not; 300 fail inside pydantic before anything is written.

docs/SECURITY_ASSESSMENT_SCOPE.md:53 lists "F1 (Self-bricking writer)" as resolved.

The tests accept either correct behaviour: the append is refused with nothing written, or the ledger
stays readable, verifiable and appendable.
"""
import pytest

from argus_ledger import AppendOnlyLedger


def _nested_lists(depth):
    value = 1
    for _ in range(depth):
        value = [value]
    return {"d": value}


def _nested_objects(depth):
    value = 1
    for _ in range(depth):
        value = {"k": value}
    return {"d": value}


def _append_deep(tmp_path, payload):
    """Returns (ledger, path, accepted)."""
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    before = path.read_bytes()
    try:
        ledger.append("tool.result", "agent_1", payload)
    except (TypeError, ValueError, RecursionError):
        assert path.read_bytes() == before, "a refused append must not leave bytes behind"
        return ledger, path, False
    return ledger, path, True


def test_control_moderately_nested_payload_round_trips(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    ledger, _, accepted = _append_deep(tmp_path, _nested_lists(50))
    assert accepted
    assert ledger.head().sequence == 2
    assert ledger.append("tool.call", "agent_1", {"n": 3}).sequence == 3
    assert ledger.verify_chain().valid


@pytest.mark.parametrize("build", [_nested_lists, _nested_objects], ids=["lists", "objects"])
@pytest.mark.parametrize("depth", [199, 210, 250])
def test_ledger_stays_appendable_after_deep_payload(tmp_path, monkeypatch, build, depth):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    ledger, _, accepted = _append_deep(tmp_path, build(depth))
    # Whether the deep payload was refused or stored, the ledger must still take the next event.
    nxt = ledger.append("tool.call", "agent_1", {"n": 3})
    assert nxt.sequence == (3 if accepted else 2)


@pytest.mark.parametrize("depth", [199, 250])
def test_accepted_deep_payload_is_readable_and_verifiable(tmp_path, monkeypatch, depth):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    ledger, _, accepted = _append_deep(tmp_path, _nested_lists(depth))
    if accepted:
        assert ledger.head().sequence == 2
        report = ledger.verify_chain()
        assert report.valid, report.error_detail
