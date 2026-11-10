"""severity: low
finding: the Python and Rust timestamp parsers accept different strings, so one stored record is "valid" for one verifier and "malformed timestamp" for the other; year 0000 makes the Python verifier raise instead of reporting.
Location: src/argus_ledger/timestamps.py:22-25 and 33-36 (`re.match` with `$`, which also matches before
a trailing newline, and `\\d`, which matches every Unicode decimal digit), timestamps.py:54
(`calendar.timegm` raises ValueError for year 0, not caught at src/argus_ledger/ledger.py:591), against
src/lib.rs:643-700 (`parse_timestamp_nanos`: ASCII digits only, but each field goes through
`str::parse`, which accepts a leading `+`).

timestamps.py:11-13 says the function "mirrors parse_timestamp_nanos in the Rust crate (same grammar,
same bounds ...) so the two sides never disagree about which records are ordered". Measured on this head,
with the timestamp inside an otherwise correct, correctly hashed second record:

  "1800000000000000000\\n"        Python valid    native invalid
  "2030-01-01T00:00:00Z\\n"       Python valid    native invalid
  full-width / Arabic-Indic digits Python valid    native invalid
  "2030-+1-01T00:00:00Z"          Python invalid  native valid
  "2030-01-01T00:00:+1Z"          Python invalid  native valid
  "2030-01-01T00:00:00+-1:00"     Python invalid  native valid
  "0000-01-01T00:00:00Z"          Python raises ValueError out of verify_chain(); native invalid

Effect: verdicts on one file differ by verifier, and a caller of `verify_chain()` gets an exception
where the contract (src/argus_ledger/ledger.py:484-493) promises a report with `first_broken_sequence`.

The first three tests need no extension. The differential test is skipped where argus_ledger_native is
not installed.
"""
import json

import pytest

from argus_ledger import AppendOnlyLedger, GENESIS_PREV_HASH, _native
from argus_ledger.hasher import compute_event_hash
from argus_ledger.timestamps import timestamp_nanos

needs_native = pytest.mark.skipif(not _native.available(), reason="argus_ledger_native extension not installed")

FULLWIDTH_YEAR = "\uff12\uff10\uff13\uff10-01-01T00:00:00Z"  # "2030" in full-width digits
ARABIC_INDIC_FRACTION = "2030-01-01T00:00:00.\u0661\u0662\u0663Z"

NOT_IN_THE_GRAMMAR = {
    "integer_with_trailing_newline": "1800000000000000000\n",
    "rfc3339_with_trailing_newline": "2030-01-01T00:00:00Z\n",
    "fullwidth_digits": FULLWIDTH_YEAR,
    "arabic_indic_fraction": ARABIC_INDIC_FRACTION,
    "signed_month": "2030-+1-01T00:00:00Z",
    "signed_second": "2030-01-01T00:00:+1Z",
    "signed_offset_hour": "2030-01-01T00:00:00+-1:00",
}


def _record(sequence, prev_hash, timestamp):
    fields = dict(
        sequence=sequence,
        event_id=f"ev_{sequence}",
        timestamp=timestamp,
        event_type="tool.call",
        actor="agent_1",
        prev_hash=prev_hash,
    )
    event_hash = compute_event_hash(payload={"n": sequence}, hash_version=2, **fields)
    record = dict(fields, payload={"n": sequence}, event_hash=event_hash, signature=None, hash_version=2)
    return json.dumps(record, separators=(",", ":")), event_hash


def _ledger(tmp_path, second_timestamp):
    first, h1 = _record(1, GENESIS_PREV_HASH, "1700000000000000000")
    second, _ = _record(2, h1, second_timestamp)
    path = tmp_path / "audit.jsonl"
    path.write_text(first + "\n" + second + "\n", encoding="utf-8")
    return AppendOnlyLedger(str(path))


def test_control_both_documented_forms_parse():
    assert timestamp_nanos("1800000000000000000") == 1800000000000000000
    assert timestamp_nanos("2030-01-01T00:00:00Z") == 1893456000000000000
    assert timestamp_nanos("2030-01-01T05:00:00+05:00") == 1893456000000000000


def test_control_ledger_with_plain_timestamp_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    assert _ledger(tmp_path, "1800000000000000000").verify_chain().valid


@pytest.mark.parametrize(
    "name",
    ["integer_with_trailing_newline", "rfc3339_with_trailing_newline", "fullwidth_digits", "arabic_indic_fraction"],
)
def test_python_parser_rejects_what_is_outside_the_documented_grammar(name):
    assert timestamp_nanos(NOT_IN_THE_GRAMMAR[name]) is None


def test_year_zero_is_malformed_not_an_exception():
    assert timestamp_nanos("0000-01-01T00:00:00Z") is None


def test_verify_chain_reports_year_zero_instead_of_raising(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    report = _ledger(tmp_path, "0000-01-01T00:00:00Z").verify_chain()
    assert not report.valid and report.first_broken_sequence == 2


@needs_native
@pytest.mark.parametrize("name", sorted(NOT_IN_THE_GRAMMAR))
def test_both_verifiers_give_the_same_verdict(tmp_path, monkeypatch, name):
    ledger = _ledger(tmp_path, NOT_IN_THE_GRAMMAR[name])
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    python = ledger.verify_chain()
    monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON")
    native = ledger.verify_chain()
    assert python.verifier == "python" and native.verifier == "native"
    assert (python.valid, python.first_broken_sequence) == (native.valid, native.first_broken_sequence), (
        f"python: {python.valid} {python.error_detail!r}; native: {native.valid} {native.error_detail!r}"
    )
