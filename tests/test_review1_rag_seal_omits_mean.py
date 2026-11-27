"""Regression test for a fixed finding (severity: low); test_attack_* now asserts the fixed behaviour.
finding: RAGTriadBinding.create() leaves triad_harmonic_mean out of evaluation_seal (and rounds the three scores to 4 decimals), so two evaluations with harmonic means 0.10 and 0.95 carry the same "seal of the full evaluation tuple".

Convention: test_attack_* asserts the correct behaviour (every stored score changes the seal).
proofweave.py:216 builds seal_raw from query/context/answer digests, three scores and passes_threshold,
not triad_harmonic_mean; the field docstring (proofweave.py:193) says "seal of the full evaluation tuple".
"""

from argus_ledger import RAGTriadBinding


def _make(mean, groundedness=0.5):
    return RAGTriadBinding.create("q", ["passage"], "answer", 0.5, groundedness, 0.5, mean, True)


def test_control_sealed_score_changes_seal():
    assert _make(0.5, groundedness=0.5).evaluation_seal != _make(0.5, groundedness=0.9).evaluation_seal


def test_attack_harmonic_mean_is_sealed():
    low, high = _make(0.10), _make(0.95)
    assert low.triad_harmonic_mean != high.triad_harmonic_mean
    assert low.evaluation_seal != high.evaluation_seal, "triad_harmonic_mean is not covered by the seal"


def test_attack_score_precision_is_sealed():
    a, b = _make(0.5, groundedness=0.50001), _make(0.5, groundedness=0.50004)
    assert a.evaluation_seal != b.evaluation_seal, "scores differing below 1e-4 share a seal"
