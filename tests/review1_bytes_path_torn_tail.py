"""severity: low
finding: with a bytes ledger_path, torn-tail recovery writes its sidecar to the str() of the bytes ("b'/dir/audit.jsonl'.torn-..."), a path that does not exist, so every append() after a crash raises LedgerCorruptionError where the same ledger opened by a str path recovers.

Convention: test_attack_* asserts the correct behaviour (bytes and str paths behave alike: either the
constructor refuses bytes, or the torn tail is set aside and the append succeeds). ledger.py:371 keeps
os.path.abspath(bytes) as bytes; ledger.py:555 formats it with an f-string.
"""

import os
import warnings

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError

TORN = b'{"sequence":2,"event_id":"half'


def _scenario(path_arg, raw_path):
    try:
        ledger = AppendOnlyLedger(path_arg)
    except (TypeError, ValueError):
        return "refused"  # refusing bytes paths up front is also correct
    ledger.append("tool.exec", "agent", {})
    with open(raw_path, "ab") as fh:
        fh.write(TORN)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ledger.append("tool.exec", "agent", {}).sequence
        except LedgerCorruptionError as exc:
            return f"LedgerCorruptionError: {exc}"[:240]


def test_control_str_path_recovers(tmp_path):
    path = os.path.join(str(tmp_path), "audit.jsonl")
    assert _scenario(path, path) == 2


def test_attack_bytes_path_recovers_or_is_refused(tmp_path):
    path = os.path.join(str(tmp_path), "audit.jsonl")
    outcome = _scenario(os.fsencode(path), path)
    assert outcome in (2, "refused"), f"bytes ledger path cannot recover a torn tail: {outcome}"
