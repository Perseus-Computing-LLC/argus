"""severity: low
finding: a newly created ledger file is never made durable: neither the constructor nor the first append() fsyncs the directory that holds it, so a crash can lose the whole file after append() has returned.
Location: src/argus_ledger/ledger.py:196-199 (`os.makedirs` + `os.open(..., O_CREAT)` + `os.close`, no
sync), ledger.py:229 (`O_CREAT` again in `_open_locked_for_append`) and ledger.py:337 (`os.fsync(fd)` on
the file only). The Rust writer does the same (src/file_ledger.rs:63-71 creates the directory and the
file, :337 and :461 call `sync_data` on the file only); that side is by reading only.

`fsync` on a file makes its contents durable, not its directory entry. On ext4/xfs/btrfs a power loss
after the first append can leave the directory without the new name, and with it every record the
writer acknowledged. README.md:20 states "`sync_data` durability" for both writers. The window is the
first append into a new file (and into a directory the constructor just created); later appends are
covered by the file fsync alone.

The test records which descriptors `os.fsync` is called on while a ledger is created in a new directory
and receives its first event.
"""
import os
import stat

from argus_ledger import AppendOnlyLedger


def _fsync_targets_during(monkeypatch, action):
    """Run `action` and return (kind, (st_dev, st_ino)) for every os.fsync call made meanwhile."""
    real_fsync = os.fsync
    seen = []

    def recording_fsync(fd):
        info = os.fstat(fd)
        seen.append(("dir" if stat.S_ISDIR(info.st_mode) else "file", (info.st_dev, info.st_ino)))
        return real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", recording_fsync)
        action()
    return seen


def _identity(path):
    info = os.stat(path)
    return (info.st_dev, info.st_ino)


def _create_and_append(path):
    AppendOnlyLedger(str(path)).append("tool.call", "agent_1", {"n": 1})


def test_control_first_append_fsyncs_the_ledger_file(tmp_path, monkeypatch):
    path = tmp_path / "state" / "audit.jsonl"
    seen = _fsync_targets_during(monkeypatch, lambda: _create_and_append(path))
    assert ("file", _identity(path)) in seen


def test_creating_a_ledger_fsyncs_its_directory(tmp_path, monkeypatch):
    path = tmp_path / "state" / "audit.jsonl"
    seen = _fsync_targets_during(monkeypatch, lambda: _create_and_append(path))
    assert ("dir", _identity(path.parent)) in seen, (
        f"the directory entry of the new ledger was never synced; fsync was called on: {seen}"
    )
