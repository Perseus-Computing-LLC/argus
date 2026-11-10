"""severity: medium
finding: the pure-Python verifier accepts stored records the native (Rust) verifier rejects as malformed: duplicate top-level members, a string or float "sequence", a string or float "hash_version".
Location: src/argus_ledger/ledger.py:147-150 (`_parse_record` is `AuditEvent.model_validate_json` in
pydantic's lax mode) and src/argus_ledger/models.py:15-36 (no strict mode, duplicate members collapse to
the last one), against src/lib.rs:216 (`AuditEvent::from_json_line`: typed fields, duplicate field is an
error). The dispatch at src/argus_ledger/ledger.py:517-519 picks one or the other by whether the optional
extension is installed, and always picks Python for an HMAC-signed ledger.

Effect: the same file gets `valid=True` from `verify_chain()` on a host without the wheel (or with
ARGUS_LEDGER_PURE_PYTHON=1, or with an HMAC key) and `valid=False, "Malformed or partial event record"`
from the native path and from `argus-verify`. With the duplicate-member form the line a human or a
first-key-wins tool reads says `"actor":"mallory"` while the record that verified is `"actor":"agent_1"`.
bindings/python/README.md:11 says the matrix test "holds the two paths to identical" verdicts; these
inputs are not in the matrix.

The first test needs no extension: no writer in this repository emits a record with a repeated member,
and the Rust side refuses it, so the Python verifier accepting it is wrong on its own. The differential
tests are skipped where argus_ledger_native is not installed.
"""
import json

import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")


def _record(sequence, prev_hash, payload):
    fields = dict(
        sequence=sequence,
        event_id=f"ev_{sequence}",
        timestamp=f"2026-01-01T00:00:0{sequence}+00:00",
        event_type="tool.call",
        actor="agent_1",
        prev_hash=prev_hash,
    )
    event_hash = compute_event_hash(payload=payload, hash_version=2, **fields)
    line = (
        '{"sequence":%d,"event_id":"%s","timestamp":"%s","event_type":"tool.call","actor":"agent_1",'
        '"payload":%s,"prev_hash":"%s","event_hash":"%s","signature":null,"hash_version":2}'
    ) % (sequence, fields["event_id"], fields["timestamp"], json.dumps(payload, separators=(",", ":")), prev_hash, event_hash)
    return line, event_hash


def _chain():
    first, h1 = _record(1, GENESIS_PREV_HASH, {"n": 1})
    second, h2 = _record(2, h1, {"n": 2})
    third, _ = _record(3, h2, {"n": 3})
    return [first, second, third]


MUTATIONS = {
    "duplicate_actor": lambda s: s.replace('"actor":"agent_1"', '"actor":"mallory","actor":"agent_1"'),
    "duplicate_payload_member": lambda s: s.replace('"payload":', '"payload":{"n":999},"payload":'),
    "sequence_as_string": lambda s: s.replace('"sequence":2,', '"sequence":"2",'),
    "sequence_as_float": lambda s: s.replace('"sequence":2,', '"sequence":2.0,'),
    "hash_version_as_string": lambda s: s.replace('"hash_version":2}', '"hash_version":"2"}'),
    "hash_version_as_float": lambda s: s.replace('"hash_version":2}', '"hash_version":2.0}'),
}


def _write(tmp_path, mutation=None):
    lines = _chain()
    if mutation is not None:
        mutated = MUTATIONS[mutation](lines[1])
        assert mutated != lines[1]
        lines[1] = mutated
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return AppendOnlyLedger(str(path))


def _python(ledger, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    report = ledger.verify_chain()
    assert report.verifier == "python"
    return report


def _native_report(ledger, monkeypatch):
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)
    report = ledger.verify_chain()
    assert report.verifier == "native"
    return report


def test_control_hand_built_chain_verifies_in_python(tmp_path, monkeypatch):
    report = _python(_write(tmp_path), monkeypatch)
    assert report.valid and report.total_events == 3


@needs_native
def test_control_hand_built_chain_verifies_natively(tmp_path, monkeypatch):
    report = _native_report(_write(tmp_path), monkeypatch)
    assert report.valid and report.total_events == 3


@pytest.mark.parametrize("mutation", ["duplicate_actor", "duplicate_payload_member"])
def test_python_verifier_rejects_a_record_with_a_repeated_member(tmp_path, monkeypatch, mutation):
    report = _python(_write(tmp_path, mutation), monkeypatch)
    assert not report.valid, "a record carrying two values for one member verified"
    assert report.first_broken_sequence == 2


@needs_native
@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_both_verifiers_give_the_same_verdict(tmp_path, monkeypatch, mutation):
    ledger = _write(tmp_path, mutation)
    python = _python(ledger, monkeypatch)
    native = _native_report(ledger, monkeypatch)
    assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
        f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
    )
