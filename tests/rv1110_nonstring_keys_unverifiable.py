"""severity: high
finding: append() accepts a payload dict with non-string keys, returns an event, and stores a record that verify_chain() rejects as tampered for ever.
Location: src/argus_ledger/canonical.py:91-93 (`_check_values` walks dict values and never looks at the
keys), src/argus_ledger/ledger.py:299-308 (hash over the caller's dict) and ledger.py:334 (the line
written is `event.model_dump_json()`, never read back or re-verified before the append returns).

The event hash is computed over `json.dumps(payload, sort_keys=True)` of the caller's object, where int
keys sort numerically (`{"2":..,"10":..}`) and a None key is spelt `"null"`. The stored line comes from
pydantic, which writes the keys as strings (`"None"` for None), and every verifier re-sorts those strings
(`{"10":..,"2":..}`). The digest of what is on disk therefore differs from the digest that was hashed and
signed. Effect: `append("metrics.snapshot", "agent", {"by_shard": {2: 7, 10: 1}})` succeeds, later
appends keep extending the chain, and both verifiers report `first_broken_sequence` at that record;
an append-only ledger has no way to repair it. `{1: "a"}` alone happens to survive, which is why the
existing suite does not see it.

The tests accept either correct behaviour: the append is refused before anything is written, or the
stored record verifies.
"""
import pytest

from argus_ledger import AppendOnlyLedger

NON_STRING_KEY_PAYLOADS = {
    "int_keys_2_and_10": {"by_shard": {2: 7, 10: 1}},
    "none_key": {"by_owner": {None: 3}},
}


def _append_then_verdict(tmp_path, payload, monkeypatch, pure_python):
    if pure_python:
        monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    else:
        monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    before = path.read_bytes()
    try:
        ledger.append("metrics.snapshot", "agent_1", payload)
    except (TypeError, ValueError):
        # Refusing is correct, provided nothing was written.
        assert path.read_bytes() == before
        return None
    return ledger.verify_chain()


def test_control_string_keys_verify(tmp_path, monkeypatch):
    report = _append_then_verdict(tmp_path, {"by_shard": {"2": 7, "10": 1}}, monkeypatch, pure_python=True)
    assert report is not None and report.valid and report.total_events == 2


def test_control_single_int_key_verifies(tmp_path, monkeypatch):
    # One int key has only one order and one spelling, so the two encodings agree.
    report = _append_then_verdict(tmp_path, {"by_shard": {7: 1}}, monkeypatch, pure_python=True)
    assert report is not None and report.valid


@pytest.mark.parametrize("name", sorted(NON_STRING_KEY_PAYLOADS))
@pytest.mark.parametrize("pure_python", [True, False], ids=["pure_python", "default_dispatch"])
def test_accepted_payload_is_verifiable(tmp_path, monkeypatch, name, pure_python):
    report = _append_then_verdict(tmp_path, NON_STRING_KEY_PAYLOADS[name], monkeypatch, pure_python)
    if report is not None:
        assert report.valid, (
            f"append() returned normally but the ledger no longer verifies: {report.error_detail} "
            f"(first_broken_sequence={report.first_broken_sequence}, verifier={report.verifier})"
        )


def test_later_appends_do_not_inherit_a_broken_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    try:
        ledger.append("metrics.snapshot", "agent_1", {"by_shard": {2: 7, 10: 1}})
    except (TypeError, ValueError):
        pass
    ledger.append("tool.call", "agent_1", {"n": 2})
    assert ledger.verify_chain().valid
