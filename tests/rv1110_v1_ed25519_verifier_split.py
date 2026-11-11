"""severity: low
finding: a format-1 ledger signed with Ed25519 verifies under the pure-Python verifier and fails at sequence 1 under the native verifier, which verify_chain() selects whenever the extension is installed.
Location: src/argus_ledger/hasher.py:111-113 and 162 (`_signed_message`: a format-1 signature covers the
bare event hash, format 2 covers domain tag + hash) against src/lib.rs:426-444
(`verify_event_hash_ed25519` always prepends SIGNATURE_DOMAIN at lib.rs:441, whatever the record's
hash_version), with the dispatch at src/argus_ledger/ledger.py:517-519 (Ed25519-keyed ledgers go to the
native verifier).

models.py:26-34 keeps format-1 records readable ("legacy ':'-joined preimage, untagged signatures") and
the Python verifier accepts an Ed25519-signed format-1 ledger and counts its records in `legacy_events`.
With argus_ledger_native installed the same `verify_chain()` call reports
"Invalid signature: missing or invalid signature at sequence 1". Without a key both verifiers accept the
same file, so only the signature rule differs. Effect: the verdict on a signed legacy ledger depends on
whether the optional wheel is installed.

How much of this exists in the field: Ed25519 signing landed on 2026-10-13 (commit 9e3a819) and hash
format 2 on 2026-10-18 (commit c5aeeba); `git tag --contains` gives v0.1.0-alpha.3 as the first tag for
both, so no tagged release wrote this combination, only builds of the branch between those two commits.
Rated low for that reason.

The records are built with the package's own format-1 hash and signature functions. Needs the
argus_ledger_native extension; without it the differential test is skipped, not passed.
"""
import json

import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash, ed25519_public_key, sign_event_hash_ed25519

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")

SEED = bytes(range(32))
PUBLIC_KEY = ed25519_public_key(SEED)


def _legacy_record(sequence, prev_hash, signed=True):
    """A record as the pre-format-2 Python writer stored it: no hash_version member."""
    fields = dict(
        sequence=sequence,
        event_id=f"ev_{sequence}",
        timestamp=f"2026-10-14T00:00:0{sequence}+00:00",
        event_type="tool.call",
        actor="agent_1",
        prev_hash=prev_hash,
    )
    payload = {"n": sequence}
    event_hash = compute_event_hash(payload=payload, hash_version=1, **fields)
    signature = sign_event_hash_ed25519(event_hash, SEED, hash_version=1) if signed else None
    record = dict(fields, payload=payload, event_hash=event_hash, signature=signature)
    return json.dumps(record, separators=(",", ":")), event_hash


def _legacy_ledger(tmp_path, signed=True, **kwargs):
    first, h1 = _legacy_record(1, GENESIS_PREV_HASH, signed)
    second, _ = _legacy_record(2, h1, signed)
    path = tmp_path / "audit.jsonl"
    path.write_text(first + "\n" + second + "\n", encoding="utf-8")
    return AppendOnlyLedger(str(path), **kwargs)


def _both(ledger, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    python = ledger.verify_chain()
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON")
    native = ledger.verify_chain()
    assert python.verifier == "python" and native.verifier == "native"
    return python, native


def test_control_python_verifier_accepts_signed_format_1_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    report = _legacy_ledger(tmp_path, verify_key=PUBLIC_KEY).verify_chain()
    assert report.valid and report.legacy_events == 2


def test_control_python_verifier_rejects_a_wrong_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    other = ed25519_public_key(bytes(range(1, 33)))
    report = _legacy_ledger(tmp_path, verify_key=other).verify_chain()
    assert not report.valid and report.first_broken_sequence == 1


@needs_native
def test_control_unkeyed_format_1_ledger_gets_one_verdict(tmp_path, monkeypatch):
    python, native = _both(_legacy_ledger(tmp_path), monkeypatch)
    assert python.valid and native.valid
    assert python.legacy_events == native.legacy_events == 2


@needs_native
def test_signed_format_1_ledger_gets_one_verdict(tmp_path, monkeypatch):
    python, native = _both(_legacy_ledger(tmp_path, verify_key=PUBLIC_KEY), monkeypatch)
    assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
        f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
    )
