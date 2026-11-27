"""Regression test for a fixed finding (severity: medium); test_attack_* now asserts the fixed behaviour.
finding: append() on a path that holds an ordinary one-line file without a final newline (a note, a token, a config value) treats the whole file as a torn record, truncates it to zero (moving its bytes to a .torn sidecar) and turns it into a ledger.

Convention: the test_attack_* test asserts the secure behaviour (append refuses a file whose bytes are
not a ledger, and the file is left as it was), so a failure proves the defect. ledger.py:456-458
classes any unparsable bytes after the last newline as a torn tail, and with no record before them
(tail None, ledger.py:461) ledger.py:486-488 cuts the file at offset 0. A torn fragment written by
this package always starts with "{"; the bytes removed here never were a record.
"""

import os
import warnings

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError

ORIGINAL = b"api_url=https://internal.example/v1"  # one line, no trailing newline


def test_control_newline_terminated_foreign_file_refused(tmp_path):
    path = os.path.join(str(tmp_path), "settings.conf")
    with open(path, "wb") as fh:
        fh.write(ORIGINAL + b"\n")
    try:
        AppendOnlyLedger(path).append("tool.exec", "agent", {})
        refused = False
    except LedgerCorruptionError:
        refused = True
    assert refused
    with open(path, "rb") as fh:
        assert fh.read() == ORIGINAL + b"\n"


def test_attack_unterminated_foreign_file_left_alone(tmp_path):
    path = os.path.join(str(tmp_path), "settings.conf")
    with open(path, "wb") as fh:
        fh.write(ORIGINAL)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            AppendOnlyLedger(path).append("tool.exec", "agent", {})
        except LedgerCorruptionError:
            pass
    with open(path, "rb") as fh:
        content = fh.read()
    assert content == ORIGINAL, f"foreign file rewritten as a ledger: {content[:60]!r}"
