"""severity: medium
finding: the directory entry of the ledger file (and of every directory created for it) is fsynced only by the append whose os.open created it, so a writer killed between that create and the flush leaves a ledger whose name is never made durable while every later append fsyncs records into it and returns success.

The flush that makes a new ledger file's name survive a crash is tied to the *call*
that created the file, not to the file: `_open_locked_for_append` sets a local
``created`` flag only when its own ``os.open(..., os.O_CREAT | os.O_EXCL, 0o600)``
created the file (src/argus_ledger/ledger.py:403, 410-412) and flushes the
directory only under ``if created:`` (ledger.py:425-426). The window between the
create and that flush contains ``fcntl.flock(fd, fcntl.LOCK_EX)`` (ledger.py:417),
which can block arbitrarily long behind another writer, the stat/inode identity
check (ledger.py:418-423) and ``_restrict_to_owner`` (ledger.py:424). A process
killed in that window — the cut of this review: a kill between two syscalls of
the write path — leaves the file on disk with its directory entry never flushed.
Every later append takes the plain-open path (ledger.py:406), so ``created`` is
False and the flush is skipped for ever: those appends fsync their records
(ledger.py:535) and return success, and nothing in the API reports or repairs
the missing flush. The same shape one level up: `_make_directories`
(ledger.py:86-98) rebuilds its ``created`` list from ``os.path.isdir`` on every
call (ledger.py:90), so directories that exist after an interrupted append are
never flushed again either — a later append flushes only the ledger's immediate
directory (ledger.py:425-426), not the parents of the tree the killed writer
created.

ledger.py:397-398 states the exact hazard the flush exists to prevent ("without
that a crash can lose the new file's name while its records were fsynced") and
README.md:95 promises "the first append creates the file (and missing
directories) and flushes the directory entry". In the state this test builds the
acknowledged records can all be lost to a crash while the library reports every
append successful, which is why this is more than cosmetic. A second writer
racing the killed one never flushes either: its ``os.open`` succeeds on the file
the killed writer created, so its ``created`` is False too.

The interrupted append is simulated the way the round brief prescribes: the
writer's own directory fsync is made to die (a child process runs ``os._exit(9)``
instead of the flush, so no cleanup of any kind runs — a real kill), and as the
failing-syscall variant, ``os.fsync`` raises ``EIO`` once at that point and the
append is allowed to fail the way the code fails. The on-disk state is then
inspected with the library's own API.
"""
import os
import stat
import subprocess
import sys

import pytest

import argus_ledger
from argus_ledger import AppendOnlyLedger

SRC = os.path.abspath(os.path.join(os.path.dirname(argus_ledger.__file__), ".."))

# Runs in a child process: append to a fresh ledger, dying exactly at the write
# path's directory fsync — after the file (or its directories) was created.
CHILD = """\
import os
import stat
import sys

sys.path.insert(0, sys.argv[1])

from argus_ledger import AppendOnlyLedger

_real_fsync = os.fsync


def die_on_dir_fsync(fd):
    if stat.S_ISDIR(os.fstat(fd).st_mode):
        sys.stdout.write("dying at the directory fsync, after the create")
        sys.stdout.flush()
        os._exit(9)  # the kill: between the creating syscall and its flush
    return _real_fsync(fd)


os.fsync = die_on_dir_fsync
AppendOnlyLedger(sys.argv[2]).append("first.append", "agent", {"n": 1})
sys.stdout.write("unexpected: the append completed without a directory fsync")
"""


@pytest.fixture
def dir_fsyncs(monkeypatch):
    """(st_dev, st_ino) of every directory whose entries os.fsync flushes."""
    seen = []
    real = os.fsync

    def spy(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            seen.append((info.st_dev, info.st_ino))
        return real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    return seen


def _inode(path):
    info = os.stat(path)
    return (info.st_dev, info.st_ino)


def _run_child(tmp_path, ledger_path):
    child = tmp_path / "killed_writer.py"
    child.write_text(CHILD, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    return subprocess.run(
        [sys.executable, str(child), SRC, str(ledger_path)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


def test_control_first_append_flushes_the_ledgers_directory(tmp_path, dir_fsyncs):
    path = tmp_path / "audit.jsonl"
    AppendOnlyLedger(str(path)).append("first.append", "agent", {"n": 1})
    assert _inode(str(tmp_path)) in dir_fsyncs


def test_control_first_append_flushes_every_directory_it_created(tmp_path, dir_fsyncs):
    path = tmp_path / "a" / "b" / "audit.jsonl"
    AppendOnlyLedger(str(path)).append("first.append", "agent", {"n": 1})
    for made in (tmp_path, tmp_path / "a", tmp_path / "a" / "b"):
        assert _inode(str(made)) in dir_fsyncs


def test_kill_between_create_and_flush_is_never_repaired(tmp_path, dir_fsyncs):
    path = tmp_path / "audit.jsonl"
    result = _run_child(tmp_path, path)
    # the writer was killed between creating the file and flushing its name
    assert result.returncode == 9, result.stdout + result.stderr
    assert os.path.exists(path), "the kill must land after the file was created"

    # The state after the kill: the ledger file exists, its directory entry was
    # never flushed, and no caller was ever told anything. The next append
    # fsyncs a record into this file before returning success, so it must also
    # flush the directory entry the killed writer left unflushed
    # (ledger.py:396-398, README.md:95) — otherwise every acknowledged record
    # of this ledger can be lost to a crash while append() keeps succeeding.
    event = AppendOnlyLedger(str(path)).append("second.append", "agent", {"n": 2})
    assert event.sequence == 1
    assert _inode(str(tmp_path)) in dir_fsyncs, (
        "append() wrote and fsynced a record into a file whose directory entry "
        "was never flushed (the creating append was killed before its flush); "
        "the flush was not retried"
    )


def test_kill_during_directory_creation_is_never_repaired(tmp_path, dir_fsyncs):
    path = tmp_path / "a" / "b" / "audit.jsonl"
    result = _run_child(tmp_path, path)
    assert result.returncode == 9, result.stdout + result.stderr
    # killed inside _make_directories' flush loop: the directories exist, none
    # of their entries was flushed, and the ledger file was not created yet.
    assert (tmp_path / "a").is_dir()
    assert (tmp_path / "a" / "b").is_dir()
    assert not path.exists()

    event = AppendOnlyLedger(str(path)).append("second.append", "agent", {"n": 2})
    assert event.sequence == 1
    missing = [
        str(d)
        for d in (tmp_path, tmp_path / "a", tmp_path / "a" / "b")
        if _inode(str(d)) not in dir_fsyncs
    ]
    assert not missing, (
        "append() returned success and fsynced its record, but the directory "
        f"entries created by the killed append were never flushed: {missing}"
    )


def test_fsync_failure_between_create_and_flush_is_never_retried(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    real = os.fsync
    fired = {"once": False}

    def fail_first_dir_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not fired["once"]:
            fired["once"] = True
            raise OSError(5, "Input/output error")
        return real(fd)

    monkeypatch.setattr(os, "fsync", fail_first_dir_fsync)
    with pytest.raises(OSError):
        AppendOnlyLedger(str(path)).append("first.append", "agent", {"n": 1})
    monkeypatch.undo()
    # the failed append left the file created but its name unflushed
    assert os.path.exists(path)
    assert os.path.getsize(path) == 0

    seen = []

    def spy(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            seen.append((info.st_dev, info.st_ino))
        return real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    event = AppendOnlyLedger(str(path)).append("second.append", "agent", {"n": 2})
    assert event.sequence == 1
    assert _inode(str(tmp_path)) in seen, (
        "append() succeeded and fsynced a record, but the directory entry whose "
        "flush failed during the creating append was never retried"
    )
