"""severity: medium
finding: torn-tail recovery never works for a ledger whose file name is longer than about 220 bytes: the sidecar name "<name>.torn-<offset>-<UTC time>" exceeds NAME_MAX, so every later append() raises LedgerCorruptionError and the ledger stays blocked until edited by hand.

Convention: the test_attack_* test asserts the documented recovery (README "Files, failed appends and
torn tails": the next append sets the fragment aside and appends), so a failure proves the defect.
The sidecar name is built at src/argus_ledger/ledger.py:555 from the full ledger name plus ~35 bytes.
"""

import os
import warnings

from argus_ledger import AppendOnlyLedger, LedgerCorruptionError

TORN = b'{"sequence":2,"event_id":"half'


def _torn_ledger(directory, name):
    path = os.path.join(directory, name)
    ledger = AppendOnlyLedger(path)
    ledger.append("tool.exec", "agent", {"n": 1})
    with open(path, "ab") as fh:
        fh.write(TORN)  # what a writer killed mid-append leaves after the last newline
    return ledger


def _append_recovers(ledger):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ledger.append("tool.exec", "agent", {"n": 2}).sequence
        except LedgerCorruptionError as exc:
            return f"LedgerCorruptionError: {exc}"[:200]


def test_control_short_name_recovers(tmp_path):
    ledger = _torn_ledger(str(tmp_path), "audit.jsonl")
    assert _append_recovers(ledger) == 2
    assert ledger.verify_chain().valid


def test_attack_long_name_recovers(tmp_path):
    name = "a" * 230 + ".jsonl"  # 236 bytes: a valid file name (NAME_MAX is 255)
    ledger = _torn_ledger(str(tmp_path), name)
    first = _append_recovers(ledger)
    second = _append_recovers(ledger)
    assert first == 2, f"append after a torn tail failed: {first}"
    assert second == 3, f"ledger still blocked on the next append: {second}"
