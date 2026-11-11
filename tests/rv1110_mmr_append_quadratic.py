"""severity: low
finding: MerkleMountainRange.append() recomputes every peak from all leaves on each call, so n appends cost on the order of n*n hash operations; the class docstring promises O(1) amortized appends.
Location: src/argus_ledger/proofweave.py:550-555 (`append` calls `_recompute_peaks`),
proofweave.py:557-568 (`_recompute_peaks` clears the peaks and rebuilds each one) and
proofweave.py:570-577 (`_compute_subtree_root` re-hashes the whole subtree from the leaf list, no memo).
The docstring at proofweave.py:541-545 says "Provides O(1) amortized appends and O(log N) inclusion
proofs"; there is also no inclusion-proof method on the class.

Measured on this head (one core, scratch script probe8.py, `m.append(f"leaf-{i}")`):
1,000 appends 0.33 s, 2,000 appends 1.29 s, 4,000 appends 5.3 s, 8,000 appends 21.0 s: four times the
time for twice the leaves. An accumulator fed one leaf per audit event stops being usable at a few
thousand events. `MerkleMountainRange` is exported from the package (`argus_ledger.__all__`); README.md:105
marks the proofweave module experimental.

The test counts SHA-256 invocations instead of measuring time. A mountain range needs one leaf hash per
append plus at most one merge per append on average, so 2 per append; the bound below allows 4.
"""
import hashlib

from argus_ledger.proofweave import MerkleMountainRange


def _sha256_calls_for(monkeypatch, leaves):
    real_sha256 = hashlib.sha256
    calls = [0]

    def counting_sha256(*args, **kwargs):
        calls[0] += 1
        return real_sha256(*args, **kwargs)

    mmr = MerkleMountainRange()
    with monkeypatch.context() as patch:
        patch.setattr(hashlib, "sha256", counting_sha256)
        for i in range(leaves):
            mmr.append(f"leaf-{i}")
    return calls[0], mmr


def test_control_peaks_and_root_are_deterministic(monkeypatch):
    calls, first = _sha256_calls_for(monkeypatch, 8)
    assert calls >= 8, "the counting wrapper did not see the leaf hashes"
    second = MerkleMountainRange()
    for i in range(8):
        second.append(f"leaf-{i}")
    assert first.get_bagged_root() == second.get_bagged_root()
    assert len(first.peaks) == 1  # 8 leaves form one perfect mountain


def test_append_cost_does_not_grow_with_the_number_of_leaves(monkeypatch):
    leaves = 512
    calls, _ = _sha256_calls_for(monkeypatch, leaves)
    assert calls <= 4 * leaves, (
        f"{leaves} appends took {calls} SHA-256 invocations ({calls / leaves:.0f} per append); "
        "an O(1) amortized accumulator needs about 2 per append"
    )


def test_doubling_the_leaves_doubles_the_work(monkeypatch):
    small, _ = _sha256_calls_for(monkeypatch, 128)
    large, _ = _sha256_calls_for(monkeypatch, 256)
    assert large <= 3 * small, f"128 leaves: {small} hashes, 256 leaves: {large} hashes"
