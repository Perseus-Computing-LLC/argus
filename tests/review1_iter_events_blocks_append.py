"""severity: low
finding: An open iter_events() iterator holds a shared flock between yields, so append() from the same process while iterating blocks forever.
iter_events() (src/argus_ledger/ledger.py:329-335) wraps _iter_records(), which takes LOCK_SH on its own
file description and keeps it until the generator is exhausted or closed (ledger.py:252-278: lock at
260-261, release at 278). append()
opens a second description and asks for LOCK_EX (ledger.py:136-137); flock locks on different
descriptions conflict even inside one process, so ``for ev in ledger.iter_events(): ledger.append(...)``
(derive a follow-up event per record) deadlocks the caller with no error. The Rust FileLedger returns
events as a Vec after unlocking. Adjacent to this round's cut: a suspended reader is a lock holder that
never releases; the effect is a blocked write, not a forbidden one.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from argus_ledger import AppendOnlyLedger

SRC = str(Path(__file__).resolve().parents[1] / "src")

SCRIPT = textwrap.dedent(
    """
    import sys
    from argus_ledger import AppendOnlyLedger

    ledger = AppendOnlyLedger(sys.argv[1])
    ledger.append("tool.call", "agent_1", {"n": 1})
    for event in ledger.iter_events():
        try:
            ledger.append("tool.review", "agent_1", {"reviewed": event.sequence})
            print("appended")
        except Exception as exc:  # a clear refusal is an acceptable outcome too
            print("refused", type(exc).__name__)
        break
    print("done")
    """
)


def test_control_append_after_iteration_completes(tmp_path):
    ledger = AppendOnlyLedger(str(tmp_path / "audit.jsonl"))
    ledger.append("tool.call", "agent_1", {"n": 1})
    events = list(ledger.iter_events())
    ledger.append("tool.review", "agent_1", {"reviewed": events[0].sequence})
    assert ledger.verify_chain().valid is True


def test_append_inside_iter_events_loop_returns(tmp_path):
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    timed_out = False
    proc = None
    try:
        proc = subprocess.run(
            [sys.executable, "-c", SCRIPT, str(tmp_path / "audit.jsonl")],
            env=env,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    assert not timed_out, "append() inside an iter_events() loop did not return within 8 s (self-deadlock)"
    assert proc.returncode == 0, proc.stderr
    assert "done" in proc.stdout
