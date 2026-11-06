"""severity: medium
finding: PraxaGovernanceGovernor moves to EXECUTED before the broker runs, so after the broker fails verify_effect() still seals a VERIFIED ProofWeaveTransaction for an action that never completed.
execute_with_broker() (src/argus_ledger/proofweave.py:336-339) sets state = EXECUTED and clears the token,
then calls broker_fn; an exception from the broker propagates but the state is not rolled back.
verify_effect() (proofweave.py:349-362) only checks state == EXECUTED ("Cannot verify effect before
execution"), so the failed step is appended to verified_transactions and the governor reports VERIFIED.
"""
import pytest

from argus_ledger import PraxaGovernanceGovernor, PraxaState

POLICY = {"prohibited_actions": []}
INTENT = {"action": "deploy", "target": "edge-1"}


class BrokerDown(Exception):
    pass


def _failing_broker(action):
    raise BrokerDown("broker unavailable")


def _honest_readback(action):
    return {"target": action["target"], "deployed": False}


def test_control_verify_effect_requires_execution():
    gov = PraxaGovernanceGovernor(POLICY)
    ok, _token = gov.evaluate_proposal(INTENT)
    assert ok is True
    with pytest.raises(RuntimeError):
        gov.verify_effect(0, INTENT, dict(INTENT), lambda action: "deployed")
    assert gov.verified_transactions == []


def test_failed_broker_call_is_not_sealed_as_verified():
    gov = PraxaGovernanceGovernor(POLICY)
    ok, token = gov.evaluate_proposal(INTENT)
    assert ok is True
    try:
        gov.execute_with_broker(token, dict(INTENT), _failing_broker)
    except Exception:
        pass  # the broker failure may propagate or be wrapped; either is fine
    try:
        gov.verify_effect(0, INTENT, dict(INTENT), _honest_readback)
    except (RuntimeError, PermissionError, ValueError):
        pass  # refusing to verify a step that did not execute is the expected outcome
    assert gov.verified_transactions == [], "a step whose broker call failed was sealed as verified"
    assert gov.state != PraxaState.VERIFIED
