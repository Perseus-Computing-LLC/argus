"""Regression test for a fixed finding (severity: medium); test_attack_* now asserts the fixed behaviour.
finding: validate_identifiers() and append() accept an event_type or actor that ends in a newline ("tool.exec\\n", "agent\\n"): the grammar regexes end in `$`, which also matches before a final "\\n", so the Python writer stores identifiers the Rust writer refuses.

Convention: each test_attack_* asserts the secure behaviour (IdentifierError, nothing written), so a
failure proves the defect. canonical.py:37 and :40 compile `^...$` patterns used with re.match at
canonical.py:67 and :73; Rust validate_identifiers (src/lib.rs:580-593) checks every byte.
"""

import os

import pytest

from argus_ledger import AppendOnlyLedger, IdentifierError, validate_identifiers


def test_control_internal_newline_rejected():
    with pytest.raises(IdentifierError):
        validate_identifiers("tool.exec", "a\nb")
    with pytest.raises(IdentifierError):
        validate_identifiers("tool\n.exec", "agent")


@pytest.mark.parametrize("event_type,actor", [("tool.exec\n", "agent"), ("tool.exec", "agent\n")])
def test_attack_trailing_newline_identifier_rejected(event_type, actor):
    with pytest.raises(IdentifierError):
        validate_identifiers(event_type, actor)


def test_attack_append_refuses_trailing_newline_actor(tmp_path):
    path = os.path.join(str(tmp_path), "audit.jsonl")
    ledger = AppendOnlyLedger(path)
    try:
        event = ledger.append("tool.exec", "agent\n", {})
    except IdentifierError:
        event = None
    assert event is None, f"append stored actor {event.actor!r}, which the Rust writer refuses"
    assert not os.path.exists(path)
