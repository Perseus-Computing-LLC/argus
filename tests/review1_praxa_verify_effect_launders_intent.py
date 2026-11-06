"""severity: medium
finding: PraxaGovernanceGovernor.verify_effect() seals a VERIFIED ProofWeaveTransaction for whatever intent and action the caller passes, including ones the policy prohibits and that were never authorized.
verify_effect() (src/argus_ledger/proofweave.py:341-362) takes ``intent`` and ``action`` from the caller
and binds them, with the governor's policy, into a ProofWeaveTransaction; the governor never stored the
intent it authorized in evaluate_proposal() (proofweave.py:320-324), so it cannot compare. After
authorizing and executing {"action": "read_report"}, a caller obtains a sealed, VERIFIED transaction
whose intent_digest is that of {"action": "drop_database"} under a policy that prohibits it: evidence
that the policy authorized an action it forbids.
"""
import hashlib

from argus_ledger import PraxaGovernanceGovernor, PraxaState, canonical_json_bytes

POLICY = {"prohibited_actions": ["drop_database"]}
AUTHORIZED = {"action": "read_report"}
PROHIBITED = {"action": "drop_database"}


def _digest(obj):
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def _executed_governor():
    gov = PraxaGovernanceGovernor(POLICY)
    ok, token = gov.evaluate_proposal(AUTHORIZED)
    assert ok is True
    gov.execute_with_broker(token, dict(AUTHORIZED), lambda action: {"ok": True})
    return gov


def test_control_verify_effect_binds_the_authorized_intent():
    gov = _executed_governor()
    tx = gov.verify_effect(0, AUTHORIZED, dict(AUTHORIZED), lambda action: "report read")
    assert tx.intent_digest == _digest(AUTHORIZED)
    assert tx.policy_snapshot_hash == gov.policy_hash
    assert gov.state == PraxaState.VERIFIED


def test_verify_effect_refuses_an_intent_that_was_not_authorized():
    gov = _executed_governor()
    try:
        gov.verify_effect(0, PROHIBITED, dict(PROHIBITED), lambda action: "database dropped")
    except (RuntimeError, PermissionError, ValueError):
        pass  # refusing, or sealing only the authorized intent, are both acceptable fixes
    sealed = [tx.intent_digest for tx in gov.verified_transactions]
    assert _digest(PROHIBITED) not in sealed, "a prohibited, never-authorized intent was sealed as verified"
