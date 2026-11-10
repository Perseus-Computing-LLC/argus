"""severity: low
finding: a pre-alpha.7 ledger holding a float the Python writer printed in exponent form now fails verify_chain() by default (native dispatch), although the changelog tells users the Python verify_chain() passes for exactly these ledgers.
Location: src/argus_ledger/ledger.py:517-519 (with the argus_ledger_native extension installed,
`verify_chain()` hands unsigned and Ed25519-signed ledgers to the Rust verifier) against
src/lib.rs:216 and the payload canonicaliser (serde_json `arbitrary_precision`: the stored number text is
hashed as stored). CHANGELOG.md:105-110 documents the Rust limitation and the way out: "the Rust side
(`argus-verify` and `FileLedger::verify_chain`) still reports `Event hash mismatch` for that record while
the Python `verify_chain()` passes ... use the Python verifier for them".

The old Python writer hashed `json.dumps` text (`1e-07`, `1.5e-05`) and stored what pydantic serialised
(`1e-7`, `0.000015`). The pure-Python verifier re-derives the `json.dumps` text and accepts the record;
the Rust verifier hashes the stored text and reports a tampered content hash. Since the native dispatch
was added, "the Python verify_chain()" is the Rust verifier wherever the wheel is installed, so the
documented escape route reports `valid=False, first_broken_sequence=1` unless the caller knows to set
ARGUS_LEDGER_PURE_PYTHON=1. The float limitation itself is known and documented; the finding is the
default path and the changelog sentence no longer matching it.

The record is built the way the pre-alpha.7 writer built it: `compute_event_hash` over the float payload
and `AuditEvent.model_dump_json()` for the stored line. Needs the argus_ledger_native extension; without
it the differential tests are skipped, not passed.
"""
import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash
from argus_ledger.models import AuditEvent

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")


def _legacy_float_ledger(tmp_path, value, hash_version):
    fields = dict(
        sequence=1,
        event_id="ev_1",
        timestamp="2026-10-01T00:00:01+00:00",
        event_type="score.recorded",
        actor="agent_1",
        prev_hash=GENESIS_PREV_HASH,
    )
    event_hash = compute_event_hash(payload={"score": value}, hash_version=hash_version, **fields)
    event = AuditEvent(payload={"score": value}, event_hash=event_hash, hash_version=hash_version, **fields)
    path = tmp_path / "audit.jsonl"
    path.write_text(event.model_dump_json() + "\n", encoding="utf-8")
    return AppendOnlyLedger(str(path))


def _python(ledger, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    return ledger.verify_chain()


def _default(ledger, monkeypatch):
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)
    return ledger.verify_chain()


@pytest.mark.parametrize("value", [1e-07, 1.5e-05, 0.5])
def test_control_pure_python_verifier_accepts_legacy_floats(tmp_path, monkeypatch, value):
    report = _python(_legacy_float_ledger(tmp_path, value, 1), monkeypatch)
    assert report.valid and report.verifier == "python"


@needs_native
@pytest.mark.parametrize("value", [0.5, 1e16, -9.865914147294541])
def test_control_plain_floats_get_one_verdict(tmp_path, monkeypatch, value):
    ledger = _legacy_float_ledger(tmp_path, value, 1)
    assert _python(ledger, monkeypatch).valid
    report = _default(ledger, monkeypatch)
    assert report.valid and report.verifier == "native"


@needs_native
@pytest.mark.parametrize("hash_version", [1, 2])
@pytest.mark.parametrize("value", [1e-07, 1.5e-05])
def test_default_verify_chain_passes_exponent_form_legacy_floats(tmp_path, monkeypatch, value, hash_version):
    ledger = _legacy_float_ledger(tmp_path, value, hash_version)
    assert _python(ledger, monkeypatch).valid
    report = _default(ledger, monkeypatch)
    assert report.valid, f"{report.verifier} verifier: {report.error_detail}"
