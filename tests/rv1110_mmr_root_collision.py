"""severity: low
finding: MerkleMountainRange hashes leaves and interior nodes the same way and bags peaks without the leaf count, so different leaf sets have the same root: any range's root equals the root of a one-leaf range.
Location: src/argus_ledger/proofweave.py:551 (leaf hash = sha256(leaf_data)), proofweave.py:576-577
(node hash = sha256(f"{left}:{right}")) and proofweave.py:579-588 (`get_bagged_root`: peaks folded with
the same `sha256(f"{peak}:{acc}")`, no size, no domain tag).

Outside the round-3 cut (not durability, verifier agreement or performance); recorded because it turned
up while measuring the append cost and neither earlier round lists it.

A leaf whose text is "<hex>:<hex>" hashes to exactly what an interior node or a bagging step over those
two hex strings hashes to. So for leaves [a, b, c] the bagged root R = sha256(peak_ab + ":" + hash_c) is
also the root of the single-leaf range [peak_ab + ":" + hash_c], and [a, b] has the root of the
single-leaf range [hash_a + ":" + hash_b]. A root therefore does not commit to which events, or how
many, were accumulated. The class docstring cites "SCITT / RFC 9943" and `create_blinded_commitment`
cites RFC 6962, which prefixes leaves with 0x00 and nodes with 0x01 for this reason. Leaf text is
caller-supplied (`append(leaf_data: str)`).
"""
import hashlib

from argus_ledger.proofweave import MerkleMountainRange


def _range(leaves):
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.append(leaf)
    return mmr


def test_control_different_plain_leaves_give_different_roots():
    assert _range(["a", "b", "c"]).get_bagged_root() != _range(["a", "b", "d"]).get_bagged_root()
    assert _range(["a", "b"]).get_bagged_root() != _range(["b", "a"]).get_bagged_root()


def test_control_same_leaves_give_the_same_root():
    assert _range(["a", "b", "c"]).get_bagged_root() == _range(["a", "b", "c"]).get_bagged_root()


def test_two_leaf_range_and_one_crafted_leaf_have_different_roots():
    two = _range(["a", "b"])
    hash_a = hashlib.sha256(b"a").hexdigest()
    hash_b = hashlib.sha256(b"b").hexdigest()
    one = _range([f"{hash_a}:{hash_b}"])
    assert len(two.leaves) != len(one.leaves)
    assert two.get_bagged_root() != one.get_bagged_root()


def test_three_leaf_range_and_one_crafted_leaf_have_different_roots():
    three = _range(["a", "b", "c"])
    assert len(three.peaks) == 2
    one = _range([f"{three.peaks[0]}:{three.peaks[1]}"])
    assert three.get_bagged_root() != one.get_bagged_root()
