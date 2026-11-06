"""severity: medium
finding: A consumed Praxa authority token is accepted again in a later cycle: the "single-use" token is a deterministic hash of intent and policy, so re-authorizing the same intent re-issues the identical token.
evaluate_proposal() (src/argus_ledger/proofweave.py:320-324) sets
current_token = sha256("PRAXA_AUTH:<intent hash>:<policy hash>")[:32]. execute_with_broker() clears it
after use (proofweave.py:336-337), so a token is single-use within one cycle, but the next
evaluate_proposal() for the same intent issues the same value again. A token captured from a finished
cycle (or computed offline by anyone who knows the intent and the policy, without ever being issued one)
is therefore accepted in the next authorization window, which belongs to whoever was issued that
window's token.
"""
import pytest

from argus_ledger import PraxaGovernanceGovernor, PraxaState

POLICY = {"prohibited_actions": ["drop_database"]}
INTENT = {"action": "transfer", "amount": 100}


def _ok_broker(action):
    return {"ok": True}


def _run_full_cycle(gov):
    ok, token = gov.evaluate_proposal(INTENT)
    assert ok is True
    gov.execute_with_broker(token, dict(INTENT), _ok_broker)
    gov.verify_effect(0, INTENT, dict(INTENT), lambda action: "done")
    assert gov.state == PraxaState.VERIFIED
    return token


def test_control_token_is_single_use_within_a_cycle():
    gov = PraxaGovernanceGovernor(POLICY)
    ok, token = gov.evaluate_proposal(INTENT)
    assert ok is True
    gov.execute_with_broker(token, dict(INTENT), _ok_broker)
    with pytest.raises(PermissionError):
        gov.execute_with_broker(token, dict(INTENT), _ok_broker)


def test_consumed_token_is_refused_in_a_later_cycle():
    gov = PraxaGovernanceGovernor(POLICY)
    consumed = _run_full_cycle(gov)

    ok, fresh = gov.evaluate_proposal(INTENT)  # a new, independent authorization
    assert ok is True
    replayed = []
    try:
        gov.execute_with_broker(consumed, dict(INTENT), lambda action: replayed.append(action) or {"ok": True})
    except (PermissionError, ValueError, RuntimeError):
        pass  # refusing the replayed token is the expected outcome
    assert replayed == [], "a token consumed in the previous cycle executed again"
    # The token issued for this cycle still works for its holder.
    gov.execute_with_broker(fresh, dict(INTENT), _ok_broker)
    assert gov.state == PraxaState.EXECUTED
