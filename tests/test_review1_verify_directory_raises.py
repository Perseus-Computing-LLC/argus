"""Regression test for a fixed finding (severity: low); test_attack_* now asserts the fixed behaviour.
finding: verify_chain() on a ledger path that is a directory reports valid=True with 0 events when the directory's st_size is 0 (an empty directory on btrfs/tmpfs-like filesystems), and raises IsADirectoryError when it is not; a missing file is reported as valid=False.

Convention: test_attack_* asserts the correct behaviour (a ChainVerificationReport with valid=False,
as for a missing file). ledger.py:774 checks only os.path.exists, which is true for a directory;
_snapshot_lines (ledger.py:180-191) opens it, takes st_size as the byte count to read and, when that
is non-zero, the first pread raises EISDIR. Same on the native and pure-Python paths.
AppendOnlyLedger("") resolves to the working directory and behaves the same.
"""

import os

import pytest

from argus_ledger import AppendOnlyLedger


def test_control_missing_file_reports_invalid(tmp_path):
    report = AppendOnlyLedger(os.path.join(str(tmp_path), "absent.jsonl")).verify_chain()
    assert report.valid is False and report.total_events == 0


@pytest.mark.parametrize("populated", [False, True], ids=["empty_dir", "non_empty_dir"])
@pytest.mark.parametrize("pure", [False, True], ids=["default_dispatch", "pure_python"])
def test_attack_directory_reports_invalid(tmp_path, monkeypatch, pure, populated):
    if pure:
        monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    directory = tmp_path / "audit.jsonl"
    directory.mkdir()  # e.g. a path typo, or a volume mounted in the ledger's place
    if populated:
        (directory / "unrelated.txt").write_text("x")
    try:
        report = AppendOnlyLedger(str(directory)).verify_chain()
    except OSError as exc:
        pytest.fail(f"verify_chain() raised {type(exc).__name__}: {exc}")
    assert report.valid is False, f"directory verified as a ledger: {report.total_events} events, valid=True"
