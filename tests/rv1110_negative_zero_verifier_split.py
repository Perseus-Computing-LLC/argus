"""severity: low
finding: a stored payload integer spelt `-0` is hashed as `0` by the Python verifier and as `-0` by the native (Rust) verifier, so the same record is valid for one and "tampered" for the other.
Location: src/argus_ledger/ledger.py:147-150 with src/argus_ledger/canonical.py:16-29 (the stored payload
is parsed to Python objects and re-serialised: `-0` becomes the int 0 and is hashed as `0`) against
src/lib.rs:216 and the verifier's payload digest (serde_json with `arbitrary_precision` keeps the number's
source text, so the digest covers `-0`). The dispatch is at src/argus_ledger/ledger.py:517-519.

Neither writer emits `-0`: Python's int has no negative zero and the Rust writer refuses it
(src/lib.rs:584-589, whose comment names this exact case: "numbers keep their source text, e.g. `-0`").
The verifiers were not given the same rule. Measured on this head with a hand-built second record:

  stored payload {"x":-0}, event hash over {"x":0}    Python valid     native: tampered at 2
  stored payload {"x":-0}, event hash over {"x":-0}   Python tampered  native valid   (scratch probe2.py)

Effect: a ledger produced by any third writer (or edited by hand and re-chained) gets opposite verdicts
from `verify_chain()` depending on whether argus_ledger_native is installed. `-0` is an integer token, so
the documented float limitation (CHANGELOG.md:105-110) does not cover it.

Only the first row is asserted here, because it can be built with the package's own hash function.
Needs the argus_ledger_native extension; without it the differential test is skipped, not passed.
"""
import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")


def _record(sequence, prev_hash, stored_payload_text, hashed_payload):
    fields = dict(
        sequence=sequence,
        event_id=f"ev_{sequence}",
        timestamp=f"2026-01-01T00:00:0{sequence}+00:00",
        event_type="tool.call",
        actor="agent_1",
        prev_hash=prev_hash,
    )
    event_hash = compute_event_hash(payload=hashed_payload, hash_version=2, **fields)
    line = (
        '{"sequence":%d,"event_id":"%s","timestamp":"%s","event_type":"tool.call","actor":"agent_1",'
        '"payload":%s,"prev_hash":"%s","event_hash":"%s","signature":null,"hash_version":2}'
    ) % (sequence, fields["event_id"], fields["timestamp"], stored_payload_text, prev_hash, event_hash)
    return line, event_hash


def _ledger(tmp_path, stored_payload_text):
    first, h1 = _record(1, GENESIS_PREV_HASH, '{"x":1}', {"x": 1})
    second, _ = _record(2, h1, stored_payload_text, {"x": 0})
    path = tmp_path / "audit.jsonl"
    path.write_text(first + "\n" + second + "\n", encoding="utf-8")
    return AppendOnlyLedger(str(path))


def _both(ledger, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    python = ledger.verify_chain()
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON")
    native = ledger.verify_chain()
    assert python.verifier == "python" and native.verifier == "native"
    return python, native


def test_control_python_verifier_accepts_plain_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    assert _ledger(tmp_path, '{"x":0}').verify_chain().valid


@needs_native
def test_control_plain_zero_gets_one_verdict(tmp_path, monkeypatch):
    python, native = _both(_ledger(tmp_path, '{"x":0}'), monkeypatch)
    assert python.valid and native.valid


@needs_native
def test_negative_zero_gets_one_verdict(tmp_path, monkeypatch):
    python, native = _both(_ledger(tmp_path, '{"x":-0}'), monkeypatch)
    assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
        f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
    )
