"""severity: medium
finding: on a signed ledger, a party without the key can add bytes to a stored record (an extra member, a shadowed duplicate payload key) and keyed verify_chain() still reports the ledger valid.
Location: src/argus_ledger/models.py:15-36 (`AuditEvent` ignores unknown members and keeps the last of
duplicate keys), src/argus_ledger/hasher.py:91-108 (`verify_event` re-hashes the parsed object, not the
stored bytes), src/argus_ledger/ledger.py:583 and 602; the native path does the same through
src/lib.rs:216 (`AuditEvent::from_json_line`).

The event hash and the signature commit to nine parsed fields. Nothing checks that the stored line holds
only those fields, once each. So with write access to the file and no signing key one can turn
`..."hash_version":2}` into `..."hash_version":2,"approved_by":"ciso"}`, or `"amount":2` into
`"amount":999999,"amount":2`, and both verifiers, HMAC and Ed25519, still answer valid. The library's own
readers return the committed values (last key wins), but the file is JSON Lines and is read by jq, log
shippers and first-key-wins parsers, which see the injected text inside a record that "verified".

docs/SECURITY_ASSESSMENT_SCOPE.md:46 states the property that fails: "An attacker modifying any byte in
an event must cause chain verification to fail at that sequence". The Rust writer already refuses
duplicate keys in what it writes (src/lib.rs:576-614); the verifiers do not hold stored records to it.
"""
import pytest

from argus_ledger import AppendOnlyLedger
from argus_ledger.hasher import ed25519_public_key

HMAC_KEY = b"argus-review-hmac-key-0123456789"
ED25519_SEED = bytes(range(32))

SCHEMES = {
    "hmac": ({"signing_key": HMAC_KEY}, {"signing_key": HMAC_KEY}),
    "ed25519": (
        {"signing_key": ED25519_SEED, "use_ed25519": True},
        {"verify_key": ed25519_public_key(ED25519_SEED)},
    ),
}

EDITS = {
    "extra_member": lambda line: line[:-1] + ',"approved_by":"ciso"}',
    "shadowed_duplicate_payload_key": lambda line: line.replace('"amount":2', '"amount":999999,"amount":2'),
}


def _signed_ledger(tmp_path, scheme):
    writer_kwargs, _ = SCHEMES[scheme]
    path = tmp_path / "audit.jsonl"
    ledger = AppendOnlyLedger(str(path), **writer_kwargs)
    ledger.append("payment.sent", "agent_1", {"amount": 1, "to": "bob"})
    ledger.append("payment.sent", "agent_1", {"amount": 2, "to": "bob"})
    ledger.append("payment.sent", "agent_1", {"amount": 3, "to": "bob"})
    return path


def _edit_record_two(path, edit):
    lines = path.read_text(encoding="utf-8").splitlines()
    edited = edit(lines[1])
    assert edited != lines[1], "the edit did not change the stored record"
    lines[1] = edited
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _verify(path, scheme):
    _, verifier_kwargs = SCHEMES[scheme]
    return AppendOnlyLedger(str(path), **verifier_kwargs).verify_chain()


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
def test_control_untouched_signed_ledger_verifies(tmp_path, scheme):
    report = _verify(_signed_ledger(tmp_path, scheme), scheme)
    assert report.valid and report.total_events == 3


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
def test_control_changed_value_is_detected(tmp_path, scheme):
    path = _signed_ledger(tmp_path, scheme)
    _edit_record_two(path, lambda line: line.replace('"amount":2', '"amount":7'))
    report = _verify(path, scheme)
    assert not report.valid and report.first_broken_sequence == 2


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
@pytest.mark.parametrize("edit", sorted(EDITS))
def test_bytes_added_to_a_signed_record_are_detected(tmp_path, scheme, edit):
    path = _signed_ledger(tmp_path, scheme)
    _edit_record_two(path, EDITS[edit])
    report = _verify(path, scheme)
    assert not report.valid, f"record 2 was edited without the key and still verifies ({report.verifier} verifier)"
    assert report.first_broken_sequence == 2
