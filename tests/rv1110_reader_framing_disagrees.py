"""severity: low
finding: the tail reader (head(), append()) and the streaming reader (verify_chain(), iter_events()) split the file into records differently, so one file is "valid" for one and "corrupted" for the other.
Location: src/argus_ledger/ledger.py:34-46 (`_tail_record`: bytes, records end at b"\\n" only, blank means
ASCII whitespace) against ledger.py:118-146 and 399-402, 419-423 (`_snapshot_lines` + `str.strip()`: text
mode with universal newlines, so a bare CR also ends a record, and blank means any Unicode whitespace
including U+001C-U+001F, U+0085, U+00A0, U+2028).

Measured on this head (pure-Python verifier; the native dispatch gets the same pre-split lines):

  file content                              verify_chain  iter_events  head()            append()
  3 records + a line holding U+0085         valid         3 events     LedgerCorruption  LedgerCorruption
  3 records + a line holding U+00A0         valid         3 events     LedgerCorruption  LedgerCorruption
  3 records + a line holding 0x1C           valid         3 events     LedgerCorruption  LedgerCorruption
  records separated by CR instead of LF     valid         3 events     LedgerCorruption  LedgerCorruption
  CR inside the last record's whitespace    broken at 3   raises       sequence 3        appends sequence 4

Effect, first four rows: the verifier calls the ledger intact while the writer refuses it for ever
("Cannot append to ledger with corrupted tail record"); bytes added to the file go unreported. Last row:
`append()` chains and signs a new record onto a tail that `verify_chain()` rejects as malformed, which is
the state the tail gate at ledger.py:277-283 exists to prevent ("Extending ... a tail the reader or the
verifier rejects would chain new records to a head nobody can confirm").

The Rust readers use a third rule (`BufRead::lines()` + `str::trim`, src/file_ledger.rs:599-615: LF only,
Unicode White_Space, which excludes U+001C-U+001F) and the Rust tail reader a fourth (ASCII whitespace,
src/file_ledger.rs:138). Measured with `argus-verify` and `FileLedger` built from this head (scratch
rust_confirm.py): CR separators and a trailing 0x1C line are valid for Python `verify_chain()` and
malformed for `argus-verify` (exit 1); a CR inside the last record is broken at 3 for Python and valid
for `argus-verify` (exit 0); a trailing U+0085 or U+00A0 line is valid for `FileLedger::verify_chain`
while `FileLedger::head` and `append` return Err.
"""
import pytest

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError


def _three_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    for n in range(1, 4):
        ledger.append("tool.call", "agent_1", {"n": n})
    return path, ledger


def _cr_before_last_comma(data):
    head, sep, tail = data.rpartition(b",")
    return head + b"\r" + sep + tail


EDITS = {
    "crlf_line_endings": lambda data: data.replace(b"\n", b"\r\n"),
    "trailing_line_u0085": lambda data: data + "\u0085\n".encode("utf-8"),
    "trailing_line_u00a0": lambda data: data + "\u00a0\n".encode("utf-8"),
    "trailing_line_0x1c": lambda data: data + b"\x1c\n",
    "cr_instead_of_lf": lambda data: data.replace(b"\n", b"\r"),
    "cr_inside_last_record": _cr_before_last_comma,
}


def _views(tmp_path, monkeypatch, edit):
    """(verifier accepts the file, tail reader accepts the file) after applying one edit."""
    monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    path, ledger = _three_records(tmp_path)
    original = path.read_bytes()
    edited = EDITS[edit](original)
    assert edited != original
    path.write_bytes(edited)
    verifier_accepts = ledger.verify_chain().valid
    try:
        tail_accepts = ledger.head().sequence == 3
    except LedgerCorruptionError:
        tail_accepts = False
    return ledger, verifier_accepts, tail_accepts


def test_control_crlf_file_is_read_the_same_way_by_both(tmp_path, monkeypatch):
    ledger, verifier_accepts, tail_accepts = _views(tmp_path, monkeypatch, "crlf_line_endings")
    assert verifier_accepts and tail_accepts
    assert ledger.append("tool.call", "agent_1", {"n": 4}).sequence == 4
    assert ledger.verify_chain().valid


@pytest.mark.parametrize("edit", sorted(set(EDITS) - {"crlf_line_endings"}))
def test_verifier_and_tail_reader_agree_on_the_file(tmp_path, monkeypatch, edit):
    _, verifier_accepts, tail_accepts = _views(tmp_path, monkeypatch, edit)
    assert verifier_accepts == tail_accepts, (
        f"verify_chain().valid={verifier_accepts} but head() {'accepts' if tail_accepts else 'rejects'} the tail"
    )


def test_append_does_not_extend_a_tail_the_verifier_rejects(tmp_path, monkeypatch):
    ledger, verifier_accepts, _ = _views(tmp_path, monkeypatch, "cr_inside_last_record")
    if verifier_accepts:
        return  # a verifier that reads the record the way the writer does is also correct
    with pytest.raises(LedgerCorruptionError):
        ledger.append("tool.call", "agent_1", {"n": 4})
