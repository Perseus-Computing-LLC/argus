"""severity: high
finding: PraxaGovernanceGovernor.execute_with_broker() hands a policy-prohibited action to the broker under an authority token issued for a different, allowed intent.
evaluate_proposal() (src/argus_ledger/proofweave.py:312-324) checks intent["action"] against
policy["prohibited_actions"] and derives the token from the intent hash, but it does not remember which
intent it authorized. execute_with_broker() (proofweave.py:326-339) only compares the presented token
with current_token and then passes whatever ``action`` the caller supplies to broker_fn: it neither checks
that the action is the authorized one nor re-applies the policy. The class promises "non-bypassable
lifecycle transitions" (proofweave.py:299-303); a token obtained for {"action": "read_report"} launders
{"action": "drop_database"} past the policy check.
"""
from argus_ledger import PraxaGovernanceGovernor, PraxaState

POLICY = {"prohibited_actions": ["drop_database"]}


def test_control_prohibited_intent_is_rejected():
    gov = PraxaGovernanceGovernor(POLICY)
    assert gov.evaluate_proposal({"action": "drop_database"}) == (False, None)
    assert gov.state == PraxaState.REJECTED


def test_control_authorized_action_reaches_the_broker():
    gov = PraxaGovernanceGovernor(POLICY)
    intent = {"action": "read_report"}
    ok, token = gov.evaluate_proposal(intent)
    assert ok is True
    seen = []
    gov.execute_with_broker(token, dict(intent), lambda action: seen.append(action) or {"ok": True})
    assert seen == [intent]
    assert gov.state == PraxaState.EXECUTED


def test_token_for_allowed_intent_does_not_execute_a_prohibited_action():
    gov = PraxaGovernanceGovernor(POLICY)
    ok, token = gov.evaluate_proposal({"action": "read_report"})
    assert ok is True
    seen = []
    try:
        gov.execute_with_broker(
            token, {"action": "drop_database"}, lambda action: seen.append(action) or {"ok": True}
        )
    except (PermissionError, ValueError, RuntimeError):
        pass  # refusing the call is the expected outcome
    assert seen == [], "the broker ran an action the policy prohibits"
    assert gov.state != PraxaState.EXECUTED
