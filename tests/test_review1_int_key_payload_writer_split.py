"""Regression test for a fixed finding (severity: low); test_attack_* now asserts the fixed behaviour.
finding: validate_payload() deliberately accepts integer object keys whose order survives storage ({1: "x"}), but append() of that payload then fails with a pydantic ValidationError (not a PayloadError) because AuditEvent.payload is typed Dict[str, Any]: the public validator and the writer disagree.

Convention: test_attack_* asserts the correct behaviour (a payload validate_payload() accepts is either
appended and verifies, or refused by append() with PayloadError). canonical.py:82-99 (_check_keys keeps
integer keys), models.py:22 (Dict[str, Any] rejects them in AuditEvent(...) at ledger.py:515).
"""

import os

from argus_ledger import AppendOnlyLedger, PayloadError, validate_payload


def test_control_string_keys_append(tmp_path):
    ledger = AppendOnlyLedger(os.path.join(str(tmp_path), "a.jsonl"))
    validate_payload({"1": "x"})
    ledger.append("tool.exec", "agent", {"1": "x"})
    assert ledger.verify_chain().valid


def test_attack_validator_and_writer_agree_on_int_keys(tmp_path):
    payload = {1: "x"}
    validate_payload(payload)  # accepted on head, by design (see _check_keys)
    ledger = AppendOnlyLedger(os.path.join(str(tmp_path), "a.jsonl"))
    try:
        ledger.append("tool.exec", "agent", payload)
        outcome = "appended" if ledger.verify_chain().valid else "appended-unverifiable"
    except PayloadError:
        outcome = "PayloadError"
    except Exception as exc:  # what head does
        outcome = f"{type(exc).__module__}.{type(exc).__name__}"
    assert outcome in ("appended", "PayloadError"), outcome
