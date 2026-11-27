"""Regression test for a fixed finding (severity: medium); test_attack_* now asserts the fixed behaviour.
finding: constructing an AppendOnlyLedger (even a read-only verify_key one) on a path that is a symlink follows it and strips group/other permissions from the target file, wherever it is: opening a ledger to verify it changes the mode of an unrelated file.

Convention: the test_attack_* test asserts the secure behaviour (the constructor does not change the
mode of a file reached through a symlink), so a failure proves the defect. ledger.py:377-379 calls
os.stat/os.chmod on the path, both of which follow symlinks; README says opening a ledger "creates
nothing". A process that verifies a ledger directory others can write (or runs as root) can be made to
chmod any file it owns.
"""

import os
import stat

from argus_ledger import AppendOnlyLedger


def test_control_regular_ledger_file_made_owner_only(tmp_path):
    path = os.path.join(str(tmp_path), "audit.jsonl")
    with open(path, "wb"):
        pass
    os.chmod(path, 0o644)
    AppendOnlyLedger(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600  # documented: existing ledger made owner-only


def test_attack_symlink_target_mode_untouched(tmp_path):
    shared = tmp_path / "elsewhere"
    shared.mkdir()
    victim = shared / "team-readable.conf"
    victim.write_text("x=1\n")
    os.chmod(victim, 0o644)
    ledger_dir = tmp_path / "ledgers"
    ledger_dir.mkdir()
    link = ledger_dir / "audit.jsonl"
    os.symlink(victim, link)

    AppendOnlyLedger(str(link), verify_key=bytes(range(32)))  # read-only: cannot even append

    mode = stat.S_IMODE(os.stat(victim).st_mode)
    assert mode == 0o644, f"symlink target {victim.name} chmodded to {mode:o} by the constructor"
