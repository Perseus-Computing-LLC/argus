"""Class-level regressions for input and path validation at the public entry points.

The review-1 regression files pin one witness per defect; these tests pin the outcome this
package chose where those files accept more than one, and the neighbouring variants of each class.
"""

import os
import stat
import threading

import pytest

from argus_ledger import (
    AgentTraceBinding,
    AppendOnlyLedger,
    IdentifierError,
    LedgerCorruptionError,
    MerkleMountainRange,
    PolicyActionBinding,
    PraxaGovernanceGovernor,
    ProofWeaveTransaction,
    RAGTriadBinding,
    validate_identifiers,
)
from argus_ledger.hasher import verify_signature


def _path(tmp_path, name="audit.jsonl"):
    return os.path.join(str(tmp_path), name)


# -- identifiers and event ids ------------------------------------------------------------------

@pytest.mark.parametrize(
    "event_type, actor",
    [("tool.exec\r", "agent"), ("tool.exec", "agent\r\n"), ("tool.exec\n\n", "agent"), ("tool.exec", "agent\x00")],
)
def test_identifier_trailing_control_refused(event_type, actor):
    with pytest.raises(IdentifierError):
        validate_identifiers(event_type, actor)


@pytest.mark.parametrize("event_id", ["", "a b", 'a"b', "a\\b", "a\nb", "\u00e9", "x" * 257, 7])
def test_event_id_outside_grammar_refused(tmp_path, event_id):
    path = _path(tmp_path)
    with pytest.raises((ValueError, TypeError)):
        AppendOnlyLedger(path).append("tool.exec", "agent", {}, event_id=event_id)
    assert not os.path.exists(path)


def test_event_id_at_cap_accepted(tmp_path):
    ledger = AppendOnlyLedger(_path(tmp_path))
    assert ledger.append("tool.exec", "agent", {}, event_id="e" * 256).event_id == "e" * 256
    assert ledger.verify_chain().valid


# -- payload keys --------------------------------------------------------------------------------

def test_int_key_payload_stored_as_written_and_verifies(tmp_path):
    ledger = AppendOnlyLedger(_path(tmp_path))
    event = ledger.append("tool.exec", "agent", {1: "x", 2: {3: "y"}})
    assert event.payload == {"1": "x", "2": {"3": "y"}}
    assert ledger.get_event(1).payload == event.payload
    assert ledger.verify_chain().valid


def test_append_stores_private_copy_of_payload(tmp_path):
    ledger = AppendOnlyLedger(_path(tmp_path))
    payload = {"k": ["v"]}
    event = ledger.append("tool.exec", "agent", payload)
    payload["k"].append("changed")
    assert event.payload == {"k": ["v"]}


@pytest.mark.parametrize(
    "build",
    [
        lambda: PolicyActionBinding.create({"args": {2: "a", 10: "b"}}, {}, "ALLOW"),
        lambda: PolicyActionBinding.create({}, {2: "a", 10: "b"}, "ALLOW"),
        lambda: AgentTraceBinding.create(0, "t", "tool", {"x": [{2: "a", 10: "b"}]}, "o"),
        lambda: ProofWeaveTransaction.create(0, {2: "a", 10: "b"}, {}, {}, "o", 1),
        lambda: MerkleMountainRange.create_blinded_commitment({2: "a", 10: "b"}),
    ],
)
def test_proofweave_unstable_keys_refused_at_any_depth(build):
    with pytest.raises(ValueError):
        build()


# -- proofweave scalars and seals ----------------------------------------------------------------

@pytest.mark.parametrize("bad", [3.0, True, "3", -1, None])
def test_proofweave_indices_must_be_ints(bad):
    with pytest.raises((TypeError, ValueError)):
        AgentTraceBinding.create(bad, "t", "tool", {}, "o")
    with pytest.raises((TypeError, ValueError)):
        ProofWeaveTransaction.create(bad, {}, {}, {}, "o", 1)
    if bad is not None:
        with pytest.raises((TypeError, ValueError)):
            ProofWeaveTransaction.create(0, {}, {}, {}, "o", bad)


def _rag(**overrides):
    args = dict(
        query="q",
        context_passages=["p"],
        answer="a",
        context_relevance=0.5,
        groundedness=0.5,
        answer_relevance=0.5,
        triad_harmonic_mean=0.5,
        passes_threshold=True,
    )
    args.update(overrides)
    return RAGTriadBinding.create(**args)


@pytest.mark.parametrize(
    "field, a, b",
    [
        ("context_relevance", 0.3, 0.30000000000000004),
        ("answer_relevance", 0.12345, 0.12346),
        ("triad_harmonic_mean", 0.0, 1e-12),
        ("passes_threshold", True, False),
    ],
)
def test_rag_seal_covers_every_field_exactly(field, a, b):
    assert _rag(**{field: a}).evaluation_seal != _rag(**{field: b}).evaluation_seal


@pytest.mark.parametrize(
    "overrides",
    [
        {"groundedness": True},
        {"groundedness": float("nan")},
        {"groundedness": 1.5},
        {"triad_harmonic_mean": "0.5"},
        {"passes_threshold": 1},
        {"context_passages": "p"},
        {"query": b"q"},
    ],
)
def test_rag_inputs_of_wrong_type_or_range_refused(overrides):
    with pytest.raises((TypeError, ValueError)):
        _rag(**overrides)


def test_rag_seal_is_deterministic():
    assert _rag().evaluation_seal == _rag().evaluation_seal


@pytest.mark.parametrize("salt", [b"x" * 15, "s" * 16, bytearray(3)])
def test_commitment_short_or_text_salt_refused(salt):
    with pytest.raises((TypeError, ValueError)):
        MerkleMountainRange.create_blinded_commitment({"a": 1}, salt=salt)


def test_commitment_with_explicit_salt_is_reproducible():
    salt = bytes(range(16))
    assert (
        MerkleMountainRange.create_blinded_commitment({"a": 1}, salt=salt)
        == MerkleMountainRange.create_blinded_commitment({"a": 1}, salt=bytearray(salt))
    )


@pytest.mark.parametrize("intent", [["action", "x"], "drop_database", {"action": None}, {"action": 0}])
def test_praxa_intent_without_named_action_rejected(intent):
    gov = PraxaGovernanceGovernor({"prohibited_actions": ["drop_database"]})
    assert gov.evaluate_proposal(intent) == (False, None)


def test_praxa_named_action_still_authorized():
    gov = PraxaGovernanceGovernor({"prohibited_actions": ["drop_database"]})
    ok, token = gov.evaluate_proposal({"action": "read_table"})
    assert ok and token


# -- keys ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("kw", ["signing_key", "verify_key"])
@pytest.mark.parametrize("key", ["k" * 32, 12345, ["k"]])
def test_non_bytes_keys_refused(tmp_path, kw, key):
    with pytest.raises(TypeError):
        AppendOnlyLedger(_path(tmp_path), **{kw: key})


def test_bytearray_signing_key_accepted(tmp_path):
    ledger = AppendOnlyLedger(_path(tmp_path), signing_key=bytearray(b"k" * 32))
    ledger.append("tool.exec", "agent", {})
    assert ledger.verify_chain().valid


def test_verify_signature_with_str_key_returns_false(tmp_path):
    ledger = AppendOnlyLedger(_path(tmp_path), signing_key=b"k" * 32)
    event = ledger.append("tool.exec", "agent", {})
    assert verify_signature(event, b"k" * 32) is True
    assert verify_signature(event, "k" * 32) is False


def test_load_key_keeps_every_byte(tmp_path):
    key_path = _path(tmp_path, "key.bin")
    raw = b"\t\n\r\x0b\x0c " + os.urandom(20) + b" \n"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    assert AppendOnlyLedger.load_key(key_path) == raw


def test_load_key_refuses_fifo(tmp_path):
    fifo = _path(tmp_path, "key.fifo")
    os.mkfifo(fifo, 0o600)
    result = {}

    def run():
        try:
            AppendOnlyLedger.load_key(fifo)
        except Exception as exc:  # noqa: BLE001 - the outcome is the type
            result["exc"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "load_key blocked on a FIFO"
    assert isinstance(result.get("exc"), PermissionError)


# -- paths ---------------------------------------------------------------------------------------

def test_bytes_and_pathlike_paths_are_decoded(tmp_path):
    path = _path(tmp_path)
    assert AppendOnlyLedger(os.fsencode(path)).ledger_path == path
    assert AppendOnlyLedger(tmp_path / "audit.jsonl").ledger_path == path


@pytest.mark.parametrize("bad", ["", b"", "a\x00b", 3, None])
def test_unusable_ledger_paths_refused(bad):
    with pytest.raises((TypeError, ValueError)):
        AppendOnlyLedger(bad)


def test_bytes_path_torn_tail_sidecar_is_next_to_ledger(tmp_path):
    path = _path(tmp_path)
    AppendOnlyLedger(path).append("tool.exec", "agent", {})
    with open(path, "ab") as fh:
        fh.write(b'{"sequence":2,"event_')
    with pytest.warns(Warning):
        AppendOnlyLedger(os.fsencode(path)).append("tool.exec", "agent", {})
    sidecars = [n for n in os.listdir(str(tmp_path)) if ".torn-" in n]
    assert len(sidecars) == 1 and sidecars[0].startswith("audit.jsonl.torn-")


@pytest.mark.parametrize("length", [200, 235, 249, 255])
def test_torn_tail_sidecar_name_fits_name_max(tmp_path, length):
    name = "a" * (length - len(".jsonl")) + ".jsonl"
    path = _path(tmp_path, name)
    ledger = AppendOnlyLedger(path)
    ledger.append("tool.exec", "agent", {})
    with open(path, "ab") as fh:
        fh.write(b'{"sequence":2,')
    with pytest.warns(Warning):
        assert ledger.append("tool.exec", "agent", {}).sequence == 2
    sidecars = [n for n in os.listdir(str(tmp_path)) if ".torn-" in n]
    assert len(sidecars) == 1 and len(os.fsencode(sidecars[0])) <= 255
    assert ledger.verify_chain().valid


@pytest.mark.parametrize("content", [b"x", b"key=value", b"[1,2", b"\x00\x01binary"])
def test_foreign_unterminated_file_never_truncated(tmp_path, content):
    path = _path(tmp_path)
    with open(path, "wb") as fh:
        fh.write(content)
    with pytest.raises(LedgerCorruptionError):
        AppendOnlyLedger(path).append("tool.exec", "agent", {})
    with open(path, "rb") as fh:
        assert fh.read() == content
    assert not [n for n in os.listdir(str(tmp_path)) if ".torn-" in n]


def test_foreign_bytes_after_records_never_truncated(tmp_path):
    path = _path(tmp_path)
    AppendOnlyLedger(path).append("tool.exec", "agent", {})
    with open(path, "ab") as fh:
        fh.write(b"not a record")
    with open(path, "rb") as fh:
        before = fh.read()
    with pytest.raises(LedgerCorruptionError):
        AppendOnlyLedger(path).append("tool.exec", "agent", {})
    with open(path, "rb") as fh:
        assert fh.read() == before


def test_append_refuses_symlink_at_ledger_path(tmp_path):
    target = _path(tmp_path, "elsewhere.txt")
    with open(target, "wb") as fh:
        fh.write(b"keep\n")
    os.chmod(target, 0o644)
    link = _path(tmp_path)
    os.symlink(target, link)
    with pytest.raises(LedgerCorruptionError):
        AppendOnlyLedger(link).append("tool.exec", "agent", {})
    with open(target, "rb") as fh:
        assert fh.read() == b"keep\n"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_append_refuses_directory_at_ledger_path(tmp_path):
    path = _path(tmp_path)
    os.mkdir(path)
    with pytest.raises(LedgerCorruptionError):
        AppendOnlyLedger(path).append("tool.exec", "agent", {})


@pytest.mark.parametrize("pure", [False, True])
def test_non_regular_paths_verify_invalid_without_blocking(tmp_path, monkeypatch, pure):
    if pure:
        monkeypatch.setenv("ARGUS_LEDGER_PURE_PYTHON", "1")
    else:
        monkeypatch.delenv("ARGUS_LEDGER_PURE_PYTHON", raising=False)
    fifo = _path(tmp_path, "audit.fifo")
    os.mkfifo(fifo, 0o600)
    directory = _path(tmp_path, "dir.jsonl")
    os.mkdir(directory)
    for path in (fifo, directory):
        ledger = AppendOnlyLedger(path)
        report = ledger.verify_chain()
        assert report.valid is False and "not a regular file" in report.error_detail
    for path in (fifo, directory):
        ledger = AppendOnlyLedger(path)
        with pytest.raises(LedgerCorruptionError):
            ledger.head()
        with pytest.raises(LedgerCorruptionError):
            list(ledger.iter_events())


def test_verify_through_file_component_reports_missing(tmp_path):
    path = _path(tmp_path, "file")
    with open(path, "wb"):
        pass
    report = AppendOnlyLedger(os.path.join(path, "audit.jsonl")).verify_chain()
    assert report.valid is False


def test_created_directories_owner_only_at_every_level(tmp_path):
    old = os.umask(0)
    try:
        path = os.path.join(str(tmp_path), "a", "b", "c", "audit.jsonl")
        AppendOnlyLedger(path).append("tool.exec", "agent", {})
    finally:
        os.umask(old)
    for level in ("a", "a/b", "a/b/c"):
        assert stat.S_IMODE(os.stat(os.path.join(str(tmp_path), level)).st_mode) == 0o700, level


def test_existing_directories_left_alone(tmp_path):
    parent = os.path.join(str(tmp_path), "shared")
    os.mkdir(parent)
    os.chmod(parent, 0o755)
    AppendOnlyLedger(os.path.join(parent, "audit.jsonl")).append("tool.exec", "agent", {})
    assert stat.S_IMODE(os.stat(parent).st_mode) == 0o755


# -- reader argument types -----------------------------------------------------------------------

@pytest.mark.parametrize("bad", [True, 1.0, "1"])
def test_reader_indices_must_be_ints(tmp_path, bad):
    ledger = AppendOnlyLedger(_path(tmp_path))
    ledger.append("tool.exec", "agent", {})
    with pytest.raises(TypeError):
        ledger.get_event(bad)
    with pytest.raises(TypeError):
        ledger.iter_events(start=bad)
    with pytest.raises(TypeError):
        ledger.iter_events(end=bad)
    assert ledger.get_event(1).sequence == 1
