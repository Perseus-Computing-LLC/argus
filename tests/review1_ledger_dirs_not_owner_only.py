"""severity: low
finding: the first append() creates missing ledger directories with the process umask (0755 under umask 022), although the constructor docstring says "the file and its missing directories are created owner-only"; the directory listing (ledger and .torn sidecar names, sizes, times) is readable by everyone.

Convention: test_attack_* asserts the documented behaviour (each directory append() creates has no
group/other bits). ledger.py:96 calls os.makedirs(directory, exist_ok=True) with the default mode;
docstrings at ledger.py:347-350 and in _open_locked_for_append promise owner-only creation.
"""

import os
import stat

import pytest

from argus_ledger import AppendOnlyLedger


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def test_control_file_is_owner_only(tmp_path, umask_022):
    path = os.path.join(str(tmp_path), "new", "audit.jsonl")
    AppendOnlyLedger(path).append("tool.exec", "agent", {})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_attack_created_directories_owner_only(tmp_path, umask_022):
    path = os.path.join(str(tmp_path), "new", "sub", "audit.jsonl")
    AppendOnlyLedger(path).append("tool.exec", "agent", {})
    for directory in (os.path.dirname(path), os.path.dirname(os.path.dirname(path))):
        mode = stat.S_IMODE(os.stat(directory).st_mode)
        assert mode & 0o077 == 0, f"{directory} created with mode {mode:o}"
