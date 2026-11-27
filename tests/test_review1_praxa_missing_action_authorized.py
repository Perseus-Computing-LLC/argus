"""Regression test for a fixed finding (severity: medium); test_attack_* now asserts the fixed behaviour.
finding: PraxaGovernanceGovernor.evaluate_proposal() authorizes, with a live token, an intent that has no "action" member (or an empty one): the prohibited-action check defaults the name to "" and so never sees {"tool": "drop_database"} or {"Action": "drop_database"}.

Convention: test_attack_* asserts the secure behaviour (an intent with no non-empty string "action"
is REJECTED and gets no token), so a failure proves the defect. proofweave.py:453-454:
`value.get("action", "")` then `not isinstance(action_name, str) or action_name in prohibited`; the
docstring (proofweave.py:441) says an intent whose action is not a string is REJECTED.
"""

import pytest

from argus_ledger import PraxaGovernanceGovernor, PraxaState

POLICY = {"prohibited_actions": ["drop_database"]}


def test_control_prohibited_and_non_string_action_rejected():
    gov = PraxaGovernanceGovernor(POLICY)
    assert gov.evaluate_proposal({"action": "drop_database"}) == (False, None)
    assert gov.evaluate_proposal({"action": 7}) == (False, None)
    ok, token = gov.evaluate_proposal({"action": "read_report"})
    assert ok and token


@pytest.mark.parametrize(
    "intent",
    [{"tool": "drop_database"}, {"Action": "drop_database"}, {"action": ""}, {}],
    ids=["other_key", "capitalised_key", "empty_action", "empty_intent"],
)
def test_attack_intent_without_action_rejected(intent):
    gov = PraxaGovernanceGovernor(POLICY)
    ok, token = gov.evaluate_proposal(intent)
    assert (ok, token) == (False, None), f"{intent!r} authorized with token {token!r}"
    assert gov.state is PraxaState.REJECTED
