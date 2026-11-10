"""Ledger write/read hardening: the sibling paths of the malformed-tail, file-mode and reader-lock fixes.

The finding tests (tests/review1_*.py) each pin one witness; these pin the rest of the class:
- append() extends only a tail that head() and verify_chain() accept (any malformed shape, any
  unparseable timestamp), and a refused append leaves the file byte-for-byte unchanged;
- every way the ledger file can come to exist or be replaced under a running writer ends with the
  records in an owner-only file at the ledger path;
- no reader (iter_events, get_event, verify_chain on both paths) holds the shared lock while the
  caller runs, so a suspended iterator neither blocks a writer nor deadlocks an append in the loop.
"""

import fcntl
import json
import os
import stat
import threading
import time

import pytest

from argus_ledger import AppendOnlyLedger
from argus_ledger.ledger import LedgerCorruptionError

THREAD_TIMEOUT_S = 20


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _run_bounded(fn):
    """Run fn in a daemon thread; return its result, or fail (instead of hanging) if it blocks."""
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # surfaced below
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(THREAD_TIMEOUT_S)
    assert not t.is_alive(), "call blocked: a lock is held where it must not be"
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --- append() extends only a tail the reader and the verifier accept --------------------------------


def _valid_record(tmp_path) -> dict:
    src = AppendOnlyLedger(str(tmp_path / "source.jsonl"))
    return json.loads(src.append("t", "a", {"n": 1}).model_dump_json())


def _mutations():
    # Each keeps "sequence" and "event_hash" (all the old writer read from the tail) and breaks the
    # record in a way head() or verify_chain() rejects as malformed. (A missing payload is not one:
    # the model defaults it to {}, and verify_chain() catches that record by its hash.)
    def drop(field):
        def f(rec):
            rec.pop(field)
            return json.dumps(rec)
        return f

    def setv(field, value):
        def f(rec):
            rec[field] = value
            return json.dumps(rec)
        return f

    return {
        "missing_actor": drop("actor"),
        "missing_prev_hash": drop("prev_hash"),
        "missing_timestamp": drop("timestamp"),
        "payload_not_object": setv("payload", "not-an-object"),
        "timestamp_garbage": setv("timestamp", "yesterday"),
        "timestamp_bad_month": setv("timestamp", "2026-13-01T00:00:00.000000+00:00"),
        "sequence_not_int": setv("sequence", [2]),
        "not_json": lambda rec: '{"sequence": 2, "event_hash": "' + rec["event_hash"],
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_append_refuses_every_tail_the_reader_or_verifier_rejects(tmp_path, name):
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 0})
    tail = _mutations()[name](_valid_record(tmp_path))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(tail + "\n")
    before = path.read_bytes()

    with pytest.raises(LedgerCorruptionError):
        ledger.append("t", "a", {"n": 2})
    assert path.read_bytes() == before, "a refused append must not write"

    # The writer refuses exactly what the readers refuse: head() or verify_chain() rejects it too.
    try:
        ledger.head()
    except LedgerCorruptionError:
        pass
    else:
        assert not ledger.verify_chain().valid


def test_append_still_extends_a_tail_without_trailing_newline(tmp_path):
    # Not malformed: only the newline was lost. The writer separates the records and the chain verifies.
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 1})
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    ledger.append("t", "a", {"n": 2})
    assert [e.sequence for e in ledger.iter_events()] == [1, 2]
    assert ledger.verify_chain().valid


# --- the ledger file is owner-only on every path by which it comes to exist ---------------------------


@pytest.fixture
def permissive_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def test_append_recreates_a_deleted_ledger_owner_only(tmp_path, permissive_umask):
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 1})
    os.unlink(path)
    ledger.append("t", "a", {"n": 2})
    assert _mode(path) == 0o600
    assert [e.sequence for e in ledger.iter_events()] == [1]


def test_append_recreates_a_ledger_whose_directory_entry_moved_owner_only(tmp_path, permissive_umask):
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 1})
    os.rename(path, tmp_path / "ledger.jsonl.1")
    ledger.append("t", "a", {"n": 2})
    assert _mode(path) == 0o600


@pytest.mark.parametrize("mode", [0o644, 0o666, 0o640, 0o604])
def test_append_makes_a_replaced_group_or_world_readable_file_owner_only(tmp_path, permissive_umask, mode):
    # Rotation tools and `touch` create the replacement under the umask, not 0600.
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 1})
    os.rename(path, tmp_path / "ledger.jsonl.1")
    path.touch()
    os.chmod(path, mode)
    ledger.append("t", "a", {"n": 2})
    assert _mode(path) == 0o600
    assert [e.sequence for e in ledger.iter_events()] == [1]


def test_open_makes_an_existing_world_readable_ledger_owner_only(tmp_path, permissive_umask):
    path = tmp_path / "ledger.jsonl"
    AppendOnlyLedger(str(path)).append("t", "a", {"n": 1})
    os.chmod(path, 0o644)
    AppendOnlyLedger(str(path))
    assert _mode(path) == 0o600


def test_open_keeps_owner_bits_of_an_owner_only_ledger(tmp_path):
    # Only group/other bits are cleared: an archived read-only ledger is not made writable by opening it.
    path = tmp_path / "ledger.jsonl"
    AppendOnlyLedger(str(path)).append("t", "a", {"n": 1})
    os.chmod(path, 0o400)
    try:
        ledger = AppendOnlyLedger(str(path))
        assert _mode(path) == 0o400
        assert ledger.verify_chain().valid
    finally:
        os.chmod(path, 0o600)


def test_writer_that_waited_across_a_rotation_appends_to_the_file_at_the_path(tmp_path):
    path = tmp_path / "ledger.jsonl"
    rotated = tmp_path / "ledger.jsonl.1"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"n": 1})

    holder = os.open(path, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    worker = threading.Thread(target=ledger.append, args=("t", "a", {"n": 2}), daemon=True)
    try:
        worker.start()
        time.sleep(0.2)  # let the writer open the current file and block on its lock
        os.rename(path, rotated)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
    worker.join(THREAD_TIMEOUT_S)
    assert not worker.is_alive()

    assert [e.sequence for e in AppendOnlyLedger(str(rotated)).iter_events()] == [1]
    fresh = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [(r["sequence"], r["payload"]) for r in fresh] == [(1, {"n": 2})]


# --- readers hold no lock while the caller runs ------------------------------------------------------


def _ledger_with(tmp_path, n, name="ledger.jsonl") -> AppendOnlyLedger:
    ledger = AppendOnlyLedger(str(tmp_path / name))
    for i in range(n):
        ledger.append("t", "a", {"n": i})
    return ledger


def test_append_inside_an_iter_events_loop_does_not_deadlock(tmp_path):
    ledger = _ledger_with(tmp_path, 3)

    def loop():
        seen = []
        for event in ledger.iter_events():
            seen.append(event.sequence)
            ledger.append("t", "a", {"during": event.sequence})
        return seen

    # The loop sees the records present when it started, not the ones it appended.
    assert _run_bounded(loop) == [1, 2, 3]
    assert [e.sequence for e in ledger.iter_events()] == [1, 2, 3, 4, 5, 6]
    assert ledger.verify_chain().valid


@pytest.mark.parametrize("start,end", [(1, None), (2, None), (1, 2), (2, 3)])
def test_suspended_iter_events_window_does_not_block_a_writer(tmp_path, start, end):
    ledger = _ledger_with(tmp_path, 4)
    it = ledger.iter_events(start=start, end=end)
    first = next(it)
    assert first.sequence == start
    event = _run_bounded(lambda: ledger.append("t", "a", {"n": "x"}))
    assert event.sequence == 5
    rest = [e.sequence for e in it]
    assert [first.sequence] + rest == list(range(start, (end if end is not None else 4) + 1))


def test_suspended_record_and_line_iterators_do_not_block_a_writer(tmp_path):
    # The two private readers behind get_event()/verify_chain() (Python path) and the native verifier.
    ledger = _ledger_with(tmp_path, 3)
    records = ledger._iter_records()
    lines = ledger._iter_lines()
    assert next(records).sequence == 1
    assert json.loads(next(lines))["sequence"] == 1
    _run_bounded(lambda: ledger.append("t", "a", {"n": "x"}))
    assert [e.sequence for e in records] == [2, 3]
    assert [json.loads(line)["sequence"] for line in lines] == [2, 3]
    records.close()
    lines.close()


def test_suspended_iterator_does_not_block_a_writer_with_its_own_ledger_object(tmp_path):
    reader = _ledger_with(tmp_path, 2)
    writer = AppendOnlyLedger(reader.ledger_path)
    it = reader.iter_events()
    next(it)
    _run_bounded(lambda: writer.append("t", "a", {"n": "x"}))
    assert [e.sequence for e in it] == [2]


def test_readers_do_not_leak_descriptors(tmp_path):
    ledger = _ledger_with(tmp_path, 3)
    fd_dir = "/proc/self/fd"
    if not os.path.isdir(fd_dir):
        pytest.skip("needs /proc/self/fd")
    before = len(os.listdir(fd_dir))
    for _ in range(20):
        it = ledger.iter_events()
        next(it)
        it.close()
        assert ledger.get_event(2).sequence == 2
        assert ledger.verify_chain().valid
        list(ledger.iter_events())
    assert len(os.listdir(fd_dir)) <= before


def test_snapshot_reader_decodes_like_a_text_file(tmp_path):
    # Non-ASCII payloads and CRLF line ends read back exactly as open(..., encoding="utf-8") reads them.
    path = tmp_path / "ledger.jsonl"
    ledger = AppendOnlyLedger(str(path))
    ledger.append("t", "a", {"text": "naïve – ✓ – \U0001F600"})
    ledger.append("t", "a", {"text": "x" * 70000})  # longer than one read block
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    events = list(ledger.iter_events())
    assert events[0].payload == {"text": "naïve – ✓ – \U0001F600"}
    assert events[1].payload == {"text": "x" * 70000}
    assert ledger.verify_chain().valid


def test_reader_on_a_missing_file_yields_nothing(tmp_path):
    ledger = AppendOnlyLedger(str(tmp_path / "ledger.jsonl"))
    assert not os.path.exists(ledger.ledger_path)  # constructing a ledger creates nothing
    assert list(ledger.iter_events()) == []
    assert ledger.get_event(1) is None
