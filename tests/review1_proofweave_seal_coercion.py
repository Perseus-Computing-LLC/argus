"""severity: low
finding: ProofWeaveTransaction.create() and AgentTraceBinding.create() seal the caller's raw step_index / timestamp_epoch_ms text (3.0, True) but store pydantic's coerced int (3, 1), so verify() with exactly the sealed inputs returns False.

Convention: test_attack_* asserts the correct behaviour (create() either refuses a non-int index or
seals the value it stores, so verify() of the same inputs is True). proofweave.py:283 and :132 format
the raw argument into seal_raw; the models' int fields (proofweave.py:258, :263, :111) coerce it.
"""

import pytest

from argus_ledger import AgentTraceBinding, ProofWeaveTransaction


def _tx(step_index=1, ts=1_700_000_000_000):
    return ProofWeaveTransaction.create(
        step_index=step_index, intent={"action": "x"}, policy={}, action={"action": "x"},
        observation_readback="ok", timestamp_epoch_ms=ts,
    )


def _verify_tx(tx):
    return tx.verify({"action": "x"}, {}, {"action": "x"}, "ok")


def test_control_int_inputs_verify():
    assert _verify_tx(_tx())
    tb = AgentTraceBinding.create(step_index=2, thought="t", tool_name="x", action_input={}, observation="o")
    assert tb.verify("t", "x", {}, "o")


@pytest.mark.parametrize("kwargs", [{"step_index": 3.0}, {"ts": True}, {"step_index": True}],
                         ids=["float_step", "bool_timestamp", "bool_step"])
def test_attack_transaction_seals_what_it_stores(kwargs):
    try:
        tx = _tx(**kwargs)
    except (TypeError, ValueError):
        return  # refusing the input is also correct
    assert _verify_tx(tx), f"sealed with {kwargs}, stored step_index={tx.step_index} ts={tx.timestamp_epoch_ms}"


def test_attack_trace_seals_what_it_stores():
    try:
        tb = AgentTraceBinding.create(step_index=2.0, thought="t", tool_name="x", action_input={}, observation="o")
    except (TypeError, ValueError):
        return
    assert tb.verify("t", "x", {}, "o"), f"stored step_index={tb.step_index!r}"
