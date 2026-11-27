"""severity: low
finding: MerkleMountainRange.create_blinded_commitment() accepts an empty (or 1-byte) salt and a non-object payload and concatenates them without a length prefix, so the "zero-knowledge" commitment is neither hiding nor binding: (1, b"2") and (12, b"") give the same commitment, and salt=b"" is a plain SHA-256 of the payload.

Convention: test_attack_* asserts the correct behaviour (a salt shorter than the 16-byte default, or a
payload that is not a dict, is refused with ValueError/TypeError). proofweave.py:599-603.
"""

import hashlib

import pytest

from argus_ledger import MerkleMountainRange, canonical_json_bytes

commit = MerkleMountainRange.create_blinded_commitment


def test_control_default_salt_hides():
    a, salt_a = commit({"ssn": "123-45-6789"})
    b, salt_b = commit({"ssn": "123-45-6789"})
    assert len(bytes.fromhex(salt_a)) == 16 and a != b


def test_attack_empty_salt_refused():
    payload = {"ssn": "123-45-6789"}
    try:
        digest, _ = commit(payload, salt=b"")
    except (TypeError, ValueError):
        return
    assert digest != hashlib.sha256(canonical_json_bytes(payload)).hexdigest(), "empty salt: commitment is the bare hash"


def test_attack_commitment_binding():
    try:
        first, _ = commit(1, salt=b"2")
        second, _ = commit(12, salt=b"")
    except (TypeError, ValueError):
        return
    assert first != second, "different (payload, salt) openings share one commitment"
