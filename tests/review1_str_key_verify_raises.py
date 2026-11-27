"""severity: low
finding: AppendOnlyLedger accepts a str signing_key or verify_key (it checks only len()), and verify_chain() on a signed ledger then raises TypeError instead of returning a report; verify_signature() raises for a str key instead of returning False.

Convention: test_attack_* asserts the correct behaviour (the constructor refuses a non-bytes key with
TypeError/ValueError, or verification returns a report). ledger.py:357 and :362 check only len();
hasher.py:120 (hmac.new) and hasher.py:155 (bytes(str)) raise TypeError inside the verifiers, and
verify_signature catches only ValueError (hasher.py:188-191).
"""

import os

import pytest

from argus_ledger import AppendOnlyLedger, ed25519_public_key, verify_signature

HMAC_KEY = b"k" * 16
SEED = bytes(range(32))


def _verify_or_refuse(path, **kwargs):
    try:
        ledger = AppendOnlyLedger(path, **kwargs)
    except (TypeError, ValueError):
        return "refused"
    try:
        return ledger.verify_chain().valid
    except TypeError as exc:
        return f"TypeError: {exc}"


def test_control_bytes_keys_verify(tmp_path):
    hp = os.path.join(str(tmp_path), "h.jsonl")
    AppendOnlyLedger(hp, signing_key=HMAC_KEY).append("tool.exec", "agent", {})
    assert AppendOnlyLedger(hp, signing_key=HMAC_KEY).verify_chain().valid
    ep = os.path.join(str(tmp_path), "e.jsonl")
    AppendOnlyLedger(ep, signing_key=SEED, use_ed25519=True).append("tool.exec", "agent", {})
    assert AppendOnlyLedger(ep, verify_key=ed25519_public_key(SEED)).verify_chain().valid


def test_attack_str_hmac_key(tmp_path):
    hp = os.path.join(str(tmp_path), "h.jsonl")
    AppendOnlyLedger(hp, signing_key=HMAC_KEY).append("tool.exec", "agent", {})
    outcome = _verify_or_refuse(hp, signing_key=HMAC_KEY.decode())  # key read in text mode
    assert outcome in ("refused", True, False), outcome


def test_attack_str_verify_key(tmp_path):
    ep = os.path.join(str(tmp_path), "e.jsonl")
    AppendOnlyLedger(ep, signing_key=SEED, use_ed25519=True).append("tool.exec", "agent", {})
    outcome = _verify_or_refuse(ep, verify_key=ed25519_public_key(SEED).decode("latin-1"))
    assert outcome in ("refused", True, False), outcome


def test_attack_verify_signature_str_key_returns_bool(tmp_path):
    hp = os.path.join(str(tmp_path), "h.jsonl")
    event = AppendOnlyLedger(hp, signing_key=HMAC_KEY).append("tool.exec", "agent", {})
    try:
        result = verify_signature(event, HMAC_KEY.decode())
    except TypeError as exc:
        pytest.fail(f"verify_signature raised TypeError: {exc}")
    assert result in (True, False)
