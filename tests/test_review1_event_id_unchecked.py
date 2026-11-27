"""Regression test for a fixed finding (severity: low); test_attack_* now asserts the fixed behaviour.
finding: append(event_id=...) stores the caller's event_id unchecked: control characters and ANSI escapes, and any size (a 4 MiB event_id makes a 4 MiB record although payloads are capped at 1 MiB), bypassing the identifier grammar applied to event_type and actor.

Convention: test_attack_* asserts the correct behaviour (append refuses such an event_id with
ValueError, before writing). ledger.py:444 `eid = event_id or str(uuid.uuid4())` is the only handling;
validate_identifiers (canonical.py:59-79) and MAX_PAYLOAD_BYTES (canonical.py:29, :142) cover the
other caller-supplied fields. The Rust writer never takes an event_id from the caller (src/lib.rs:1193).
"""

import os

import pytest

from argus_ledger import AppendOnlyLedger, IdentifierError
from argus_ledger.canonical import MAX_PAYLOAD_BYTES


def test_control_uuid_event_id_accepted(tmp_path):
    ledger = AppendOnlyLedger(os.path.join(str(tmp_path), "a.jsonl"))
    event = ledger.append("tool.exec", "agent", {}, event_id="0b7c6f0e-2f5c-4f86-9d0b-8c1d3f1e2a10")
    assert event.event_id == "0b7c6f0e-2f5c-4f86-9d0b-8c1d3f1e2a10"
    with pytest.raises(IdentifierError):
        ledger.append("tool.exec", "agent\x1b[2K", {})  # the same bytes are refused in actor


@pytest.mark.parametrize(
    "event_id",
    ["evt-1\n\x1b[2K\rforged log line", "x" * (4 * MAX_PAYLOAD_BYTES)],
    ids=["control_chars", "4MiB"],
)
def test_attack_hostile_event_id_refused(tmp_path, event_id):
    path = os.path.join(str(tmp_path), "a.jsonl")
    ledger = AppendOnlyLedger(path)
    try:
        ledger.append("tool.exec", "agent", {}, event_id=event_id)
        stored = os.path.getsize(path)
    except ValueError:
        stored = None
    assert stored is None, f"event_id of {len(event_id)} chars stored; record is {stored} bytes"
