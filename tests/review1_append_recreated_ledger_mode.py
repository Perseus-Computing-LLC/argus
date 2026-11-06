"""severity: medium
finding: A live AppendOnlyLedger whose file was rotated or removed recreates it with the process umask (0644 under umask 022) instead of owner-only 0600.
__init__ creates the file with os.open(..., 0o600) (src/argus_ledger/ledger.py:109-111) and documents "The
ledger file is created owner-only (0600)" (ledger.py:88); the README says the Python package writes its
JSONL file "with 0600 permissions". append() however opens the path with open(path, "a+")
(ledger.py:136), which creates a missing file with mode 0666 & ~umask. A handle that outlives the file it
was constructed for (log rotation, an operator moving the ledger aside) writes its next record, a new
genesis record with its payload, into a group- and world-readable file. The Rust FileLedger opens every
append with mode(0o600) and create(true) (src/file_ledger.rs:376-379).
"""
import os
import stat

import pytest

from argus_ledger import AppendOnlyLedger


@pytest.fixture
def umask_022():
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_control_constructor_creates_owner_only_file(tmp_path, umask_022):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    assert _mode(path) == 0o600


def test_append_after_rotation_recreates_an_owner_only_file(tmp_path, umask_022):
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("tool.call", "agent_1", {"n": 1})
    os.rename(path, tmp_path / "audit.jsonl.1")  # rotated away while the writer keeps running
    ledger.append("tool.call", "agent_1", {"file": "/home/alice/notes.txt"})
    assert path.exists()
    assert _mode(path) == 0o600, f"recreated ledger file has mode {_mode(path):o}, not 600"
