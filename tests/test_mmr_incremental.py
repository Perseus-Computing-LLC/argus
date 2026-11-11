"""MerkleMountainRange: the incremental peaks and root equal a from-scratch computation.

The reference below rebuilds every mountain from the leaf texts with the documented scheme
(leaf 0x00, node 0x01, root 0x02 with the leaf count) and shares no code with the class.
"""

import hashlib

from argus_ledger.proofweave import MerkleMountainRange


def _leaf(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).digest()


def _subtree(leaves):
    if len(leaves) == 1:
        return leaves[0]
    half = len(leaves) // 2
    return hashlib.sha256(b"\x01" + _subtree(leaves[:half]) + _subtree(leaves[half:])).digest()


def _reference(texts):
    """(leaf hashes, peaks, root) for ``texts``, computed from nothing."""
    leaves = [_leaf(text) for text in texts]
    peaks = []
    offset = 0
    for power in range(63, -1, -1):
        size = 1 << power
        if len(leaves) - offset >= size:
            peaks.append(_subtree(leaves[offset:offset + size]))
            offset += size
    root = hashlib.sha256(b"\x02" + len(leaves).to_bytes(8, "big") + b"".join(peaks)).hexdigest()
    return [leaf.hex() for leaf in leaves], [peak.hex() for peak in peaks], root


def test_incremental_equals_from_scratch_for_0_to_70_leaves():
    mmr = MerkleMountainRange()
    roots = set()
    for count in range(71):
        texts = [f"leaf-{i}" for i in range(count)]
        leaves, peaks, root = _reference(texts)
        assert mmr.leaves == leaves, count
        assert mmr.peaks == peaks, count
        assert mmr.get_bagged_root() == root, count
        assert len(mmr.peaks) == bin(count).count("1"), count
        roots.add(root)
        assert mmr.append(f"leaf-{count}") == count
    assert len(roots) == 71  # every size has its own root, the empty range included


def test_root_binds_the_leaf_count_and_the_kind_of_hash():
    one = MerkleMountainRange()
    one.append("a")
    # A single leaf, its only peak and the root are three different values.
    assert one.leaves == one.peaks
    assert one.get_bagged_root() != one.leaves[0]
    assert one.leaves[0] != hashlib.sha256(b"a").hexdigest()

    two = MerkleMountainRange()
    two.append("a")
    two.append("b")
    assert len(two.peaks) == 1
    assert two.peaks[0] not in two.leaves
    assert two.get_bagged_root() != one.get_bagged_root()
