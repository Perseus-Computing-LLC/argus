"""severity: low
finding: PolicyActionBinding.create() hashes intent/policy with canonical_json_bytes but without validate_payload, so an intent with integer keys ({2: ..., 10: ...}) is digested in integer order; after the intent is stored and reloaded as JSON (string keys) verify() returns False for the same intent.

Convention: test_attack_* asserts the correct behaviour (create() refuses the intent with
PayloadError/ValueError, or verify() of its JSON round-trip is True). proofweave.py:56-58 hash
canonical_json_bytes(intent/policy/evidence); canonical.py:82-99 is the check the ledger writer applies
to the same problem (see json.dumps sort order notes at canonical.py:85-89).
"""

import json

from argus_ledger import PolicyActionBinding


def _roundtrip(obj):
    return json.loads(json.dumps(obj))


def test_control_string_keys_roundtrip():
    intent = {"action": "read", "args": {"2": "a", "10": "b"}}
    binding = PolicyActionBinding.create(intent=intent, policy={"v": 1}, verdict="allow")
    assert binding.verify(_roundtrip(intent), _roundtrip({"v": 1}))


def test_attack_int_keys_refused_or_roundtrip():
    intent = {"action": "read", "args": {2: "a", 10: "b"}}
    try:
        binding = PolicyActionBinding.create(intent=intent, policy={"v": 1}, verdict="allow")
    except ValueError:
        return
    assert binding.verify(_roundtrip(intent), {"v": 1}), "binding no longer verifies its own intent once stored as JSON"
