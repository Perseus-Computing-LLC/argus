"""severity: low
finding: a stored record whose payload is not a JSON object (`[1]`, `"s"`, `null`, `7`) is "valid" for the native (Rust) verifier and "malformed" for the Python verifier, and Python head()/append() refuse a tail the Rust verifier and writer accept.
Location: src/argus_ledger/models.py:22 (`payload: Dict[str, Any]`, enforced when a stored line is parsed
at src/argus_ledger/ledger.py:147-150) against src/lib.rs:216 (`AuditEvent::from_json_line` keeps the
payload as text, src/lib.rs:85, and nothing on the verify path checks its type). The object rule exists
on the Rust side only in the writer's gate (src/lib.rs:601, `!value.is_object()`); the verifier was not
given it. The dispatch is at src/argus_ledger/ledger.py:517-519.

Both writers refuse such a payload, so only a third writer or someone with write access to the file can
store one; the two verifiers then disagree about it. Measured on this head with a hand-built second
record whose event hash is computed over the stored payload text:

  payload   Python verify_chain   native verify_chain   argus-verify   FileLedger verify / head / append
  [1]       malformed at 2        valid                 exit 0         valid / Ok / Ok (sequence 3)
  "s"       malformed at 2        valid                 exit 0         valid / Ok / Ok
  null      malformed at 2        valid                 exit 0         valid / Ok / Ok
  7         malformed at 2        valid                 exit 0         valid / Ok / Ok

(`argus-verify` and `FileLedger` built from this head: scratch probe11.py.) With such a record at the
tail, Python `head()` and `append()` raise LedgerCorruptionError while the Rust `FileLedger::append`
chains the next record onto it.

Effect: `verify_chain()` gives opposite verdicts for one file depending on whether argus_ledger_native is
installed (or ARGUS_LEDGER_PURE_PYTHON is set, or an HMAC key is passed), and the Rust verifier reports a
ledger as intact that holds a record neither writer could have produced.

Needs the argus_ledger_native extension; without it the differential tests are skipped, not passed.
"""
import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")

NON_OBJECT_PAYLOADS = {"array": ("[1]", [1]), "string": ('"s"', "s"), "null": ("null", None), "integer": ("7", 7)}


def _record(sequence, prev_hash, payload_text, payload_value):
    fields = dict(
        sequence=sequence,
        event_id=f"ev_{sequence}",
        timestamp=f"2026-01-01T00:00:0{sequence}+00:00",
        event_type="tool.call",
        actor="agent_1",
        prev_hash=prev_hash,
    )
    event_hash = compute_event_hash(payload=payload_value, hash_version=2, **fields)
    line = (
        '{"sequence":%d,"event_id":"%s","timestamp":"%s","event_type":"tool.call","actor":"agent_1",'
        '"payload":%s,"prev_hash":"%s","event_hash":"%s","signature":null,"hash_version":2}'
    ) % (sequence, fields["event_id"], fields["timestamp"], payload_text, prev_hash, event_hash)
    return line, event_hash


def _ledger(tmp_path, payload_text, payload_value):
    first, h1 = _record(1, GENESIS_PREV_HASH, '{"x":1}', {"x": 1})
    second, _ = _record(2, h1, payload_text, payload_value)
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


def test_control_python_verifier_accepts_an_object_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    report = _ledger(tmp_path, '{"x":2}', {"x": 2}).verify_chain()
    assert report.valid and report.total_events == 2


@needs_native
def test_control_object_payload_gets_one_verdict(tmp_path, monkeypatch):
    python, native = _both(_ledger(tmp_path, '{"x":2}', {"x": 2}), monkeypatch)
    assert python.valid and native.valid


@needs_native
def test_control_native_verifier_checks_the_hash_of_the_crafted_record(tmp_path, monkeypatch):
    # The hand-built hash is the one the native verifier expects: changing the stored text breaks it.
    ledger = _ledger(tmp_path, "[1]", [2])
    native = ledger.verify_chain()
    assert native.verifier == "native" and not native.valid and native.first_broken_sequence == 2


@needs_native
@pytest.mark.parametrize("kind", sorted(NON_OBJECT_PAYLOADS))
def test_non_object_payload_gets_one_verdict(tmp_path, monkeypatch, kind):
    python, native = _both(_ledger(tmp_path, *NON_OBJECT_PAYLOADS[kind]), monkeypatch)
    assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
        f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
    )
